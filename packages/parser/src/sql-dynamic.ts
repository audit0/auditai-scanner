import { groupEnd, isPunct, isWord, splitSqlStatements, type Token } from "./sql-lexer.js";

/**
 * Parameters of a PL/pgSQL function that reach the text of a dynamic statement unquoted: glued in
 * with `||`, passed to `format()` through `%s`, or run whole (`execute p_sql`). Whoever calls the
 * function then writes part of the SQL it runs (CWE-89).
 *
 * A parameter is safe where it goes through `USING`, `quote_literal`, `quote_nullable`,
 * `quote_ident`, `format` `%L` / `%I`, or a cast to a type that cannot carry SQL (`::int`,
 * `::uuid`, `::regclass`). Only text-like parameters count: an integer or uuid glued into a string
 * cannot close the quote. A parameter the body compares with a list of literals (`if p_col not in
 * ('a', 'b') then raise`, `= any (array['a', 'b'])`) is an allow-list and does not count either.
 *
 * Local variables carry the taint one assignment at a time: `v_sql := 'select ... ' || p_status;
 * execute v_sql;` counts. Text matching over the lexer's tokens; never throws.
 */
export function paramsReachingExecute(
  body: string,
  params: ReadonlyArray<{ name: string; type: string }>,
): string[] {
  const candidates = params
    .filter((p) => TEXT_LIKE.test(p.type.trim()))
    .map((p) => p.name.toLowerCase())
    .filter((n) => n !== "");
  if (candidates.length === 0 || !EXECUTE_WORD.test(body)) return [];
  const statements = splitSqlStatements(body).map((s) => s.tokens);
  const guarded = new Set(candidates.filter((n) => isAllowListed(statements, n)));
  const params0 = candidates.filter((n) => !guarded.has(n));
  if (params0.length === 0) return [];

  // Taint: name -> the parameters it carries.
  const taint = new Map<string, Set<string>>(params0.map((n) => [n, new Set([n])]));
  const assignments = statements.flatMap(assignmentsIn);
  for (let pass = 0; pass < MAX_PASSES; pass += 1) {
    let changed = false;
    for (const a of assignments) {
      const carried = unsafeNames(a.expr, taint);
      if (carried.size === 0) continue;
      const own = taint.get(a.target) ?? new Set<string>();
      const before = own.size;
      for (const p of carried) own.add(p);
      if (own.size !== before) {
        taint.set(a.target, own);
        changed = true;
      }
    }
    if (!changed) break;
  }

  const out: string[] = [];
  for (const tokens of statements) {
    for (const expr of executedExpressions(tokens)) {
      for (const p of unsafeNames(expr, taint)) if (!out.includes(p)) out.push(p);
    }
  }
  return params0.filter((p) => out.includes(p));
}

/** Types whose value can close a quote once glued into SQL text. */
const TEXT_LIKE =
  /^(?:text|varchar|character varying|char|character|bpchar|citext|name|json|jsonb|anyelement)(?:\s*\(\s*\d+\s*\))?(?:\s*\[\s*\])?$/i;
const EXECUTE_WORD = /(?<![A-Za-z0-9_$])execute(?![A-Za-z0-9_$])/i;
const MAX_PASSES = 8;
const QUOTING = new Set(["quote_literal", "quote_nullable", "quote_ident"]);
/** Casts after which the value cannot carry SQL text. `regclass` resolves and re-quotes a relation name. */
const SAFE_CAST =
  /^(?:int|int2|int4|int8|integer|smallint|bigint|numeric|decimal|real|float|float4|float8|double|uuid|bool|boolean|date|timestamp|timestamptz|time|interval|regclass|regproc|regprocedure|regtype|regnamespace|oid)$/;
/** Words that end the statement text of an EXECUTE (or `open ... for execute`, `for r in execute ... loop`). */
const EXECUTE_END = new Set(["using", "into", "loop"]);

function nameOf(t: Token | undefined): string | null {
  if (t === undefined) return null;
  if (t.kind === "word") return t.value;
  if (t.kind === "ident") return t.value.toLowerCase();
  return null;
}

/** The statement text of each EXECUTE in a statement: tokens after the keyword up to USING / INTO / LOOP. */
function executedExpressions(tokens: readonly Token[]): Token[][] {
  const out: Token[][] = [];
  for (let i = 0; i < tokens.length; i += 1) {
    if (!isWord(tokens[i], "execute")) continue;
    const next = tokens[i + 1];
    // EXECUTE FUNCTION / PROCEDURE belongs to CREATE TRIGGER; GRANT EXECUTE is a privilege.
    if (isWord(next, "function") || isWord(next, "procedure")) continue;
    const prev = tokens[i - 1];
    if (isWord(prev, "grant") || isWord(prev, "revoke") || isPunct(prev, ",")) continue;
    let depth = 0;
    let j = i + 1;
    for (; j < tokens.length; j += 1) {
      const t = tokens[j];
      if (isPunct(t, "(") || isPunct(t, "[")) depth += 1;
      else if (isPunct(t, ")") || isPunct(t, "]")) depth = Math.max(0, depth - 1);
      else if (depth === 0 && t?.kind === "word" && EXECUTE_END.has(t.value)) break;
    }
    out.push(tokens.slice(i + 1, j));
    i = j - 1;
  }
  return out;
}

/** `v_sql := expr` (PL/pgSQL assignment), with the assigned name lowercased. */
function assignmentsIn(tokens: readonly Token[]): Array<{ target: string; expr: Token[] }> {
  const out: Array<{ target: string; expr: Token[] }> = [];
  for (let i = 1; i < tokens.length; i += 1) {
    // The lexer reads `:=` as `:` and `=`, side by side.
    const colon = tokens[i];
    const eq = tokens[i + 1];
    if (colon?.raw !== ":" || eq?.raw !== "=" || eq.start !== colon.end) continue;
    const target = nameOf(tokens[i - 1]);
    if (target === null || isPunct(tokens[i - 2], ".")) continue;
    out.push({ target, expr: tokens.slice(i + 2) });
  }
  return out;
}

/**
 * The parameters carried by names used unquoted in an expression. Quoting calls hide their argument;
 * `format()` hides the arguments that fill `%L` and `%I` and keeps those that fill `%s`.
 */
function unsafeNames(
  expr: readonly Token[],
  taint: ReadonlyMap<string, ReadonlySet<string>>,
): Set<string> {
  const out = new Set<string>();
  const visit = (tokens: readonly Token[]): void => {
    for (let i = 0; i < tokens.length; i += 1) {
      const t = tokens[i];
      // `case when p_filter is not null then 'and x = $6' else '' end`: the condition only picks a
      // branch; what reaches the text is the branch, read on its own after THEN or ELSE.
      if (isWord(t, "when")) {
        i = thenAfter(tokens, i);
        continue;
      }
      const name = nameOf(t);
      if (name === null) continue;
      const open = tokens[i + 1];
      if (isPunct(open, "(")) {
        const close = groupEnd(tokens, i + 1);
        if (QUOTING.has(name)) {
          i = close;
          continue;
        }
        if (name === "format") {
          visitFormat(tokens.slice(i + 2, close), visit);
          i = close;
          continue;
        }
        // Any other call: its arguments are read as they come.
        continue;
      }
      const carried = taint.get(name);
      if (carried === undefined) continue;
      if (isPunct(tokens[i - 1], ".")) continue;
      if (isSafeCast(tokens, i + 1)) continue;
      for (const p of carried) out.add(p);
    }
  };
  visit(expr);
  return out;
}

/** Index of the THEN that closes the WHEN at `at` (same paren depth), or the last token. */
function thenAfter(tokens: readonly Token[], at: number): number {
  let depth = 0;
  for (let j = at + 1; j < tokens.length; j += 1) {
    const t = tokens[j];
    if (isPunct(t, "(") || isPunct(t, "[")) depth += 1;
    else if (isPunct(t, ")") || isPunct(t, "]")) depth -= 1;
    if (depth < 0) return j - 1;
    if (depth === 0 && isWord(t, "then")) return j;
  }
  return tokens.length - 1;
}

/**
 * The body refuses callers without a privilege before its first EXECUTE: it reads the caller's identity
 * (`auth.uid()`, `auth.jwt()`) or calls an `is_admin()`-style helper, and raises, with an admin-like
 * literal or that helper in the text before the EXECUTE. A SQL runner kept for admins is a design choice,
 * not an injection by strangers; whether a user can make themselves admin is S6's question.
 */
export function executeGatedByCaller(body: string): boolean {
  const at = body.search(EXECUTE_WORD);
  if (at < 0) return false;
  const before = body.slice(0, at);
  if (!/(?<![A-Za-z0-9_$])raise(?![A-Za-z0-9_$])/i.test(before)) return false;
  if (ADMIN_HELPER.test(before)) return true;
  if (!/auth\s*\.\s*(?:uid|jwt)\s*\(/i.test(before)) return false;
  return [...before.matchAll(/'([^']*)'/g)].some((m) => ADMIN_LITERAL.test(m[1] ?? ""));
}

const ADMIN_HELPER =
  /(?<![A-Za-z0-9_$])(?:is_?(?:super_?|platform_?|org_?)?admin|has_?role|check_?admin|require_?admin)\s*\(/i;
const ADMIN_LITERAL =
  /^(?:admin|admins|administrator|super_?admin|superadmin|superuser|owner|staff|platform_admin|system_admin)$/i;

/** `x::int`, `x::regclass::text`: the first cast decides. */
function isSafeCast(tokens: readonly Token[], at: number): boolean {
  if (!isPunct(tokens[at], "::")) return false;
  const type = nameOf(tokens[at + 1]);
  return type !== null && SAFE_CAST.test(type);
}

function visitFormat(inner: readonly Token[], visit: (tokens: readonly Token[]) => void): void {
  const args = splitArgs(inner);
  const [fmt, ...rest] = args;
  if (fmt === undefined) return;
  const only = fmt.length === 1 ? fmt[0] : undefined;
  if (only?.kind !== "string") {
    // A format string built at run time: every argument may land anywhere.
    for (const a of args) visit(a);
    return;
  }
  const kinds = formatSpecifiers(only.value);
  rest.forEach((arg, idx) => {
    const kind = kinds.get(idx + 1);
    // An argument no specifier uses never reaches the text; %I and %L quote it.
    if (kind === "s") visit(arg);
  });
}

function splitArgs(tokens: readonly Token[]): Token[][] {
  const out: Token[][] = [];
  let cur: Token[] = [];
  let depth = 0;
  for (const t of tokens) {
    if (isPunct(t, "(") || isPunct(t, "[")) depth += 1;
    else if (isPunct(t, ")") || isPunct(t, "]")) depth = Math.max(0, depth - 1);
    if (depth === 0 && isPunct(t, ",")) {
      out.push(cur);
      cur = [];
    } else cur.push(t);
  }
  out.push(cur);
  return out;
}

/**
 * Which argument (1-based) each conversion of a format string consumes, and how: `%s`, `%I`, `%L`,
 * with positions (`%2$s`), widths (`%-10s`, `%*s`) and `%%`. A position used both ways counts as `s`.
 */
export function formatSpecifiers(fmt: string): Map<number, "s" | "I" | "L"> {
  const out = new Map<number, "s" | "I" | "L">();
  const spec = /%(?:(\d+)\$)?([-]?)(\*(?:\d+\$)?|\d+)?([sIL%])/g;
  let next = 1;
  for (const m of fmt.matchAll(spec)) {
    const kind = m[4] as "s" | "I" | "L" | "%";
    if (kind === "%") continue;
    const width = m[3];
    if (width?.startsWith("*")) {
      const pos = /^\*(\d+)\$$/.exec(width)?.[1];
      next = pos !== undefined ? Number(pos) + 1 : next + 1;
    }
    const n = m[1] !== undefined ? Number(m[1]) : next;
    next = n + 1;
    const prev = out.get(n);
    out.set(n, prev === "s" ? "s" : kind);
  }
  return out;
}

/**
 * The body compares the parameter with literals only: `p in ('a', 'b')`, `p not in (...)`,
 * `p = any (array['a', 'b'])` or `p <> all (...)`. Such a body either raises or never runs the
 * statement for any other value, so the parameter is an allow-list, not free text.
 */
function isAllowListed(statements: readonly Token[][], param: string): boolean {
  for (const tokens of statements) {
    for (let i = 0; i < tokens.length; i += 1) {
      if (nameOf(tokens[i]) !== param || isPunct(tokens[i - 1], ".")) continue;
      let j = i + 1;
      if (isWord(tokens[j], "not")) j += 1;
      let open = -1;
      if (isWord(tokens[j], "in") && isPunct(tokens[j + 1], "(")) open = j + 1;
      const op = tokens[j];
      if (
        op?.kind === "op" &&
        (op.raw === "=" || op.raw === "<>" || op.raw === "!=") &&
        (isWord(tokens[j + 1], "any") || isWord(tokens[j + 1], "all")) &&
        isPunct(tokens[j + 2], "(")
      ) {
        open = j + 2;
      }
      if (open === -1) continue;
      const inner = tokens.slice(open + 1, groupEnd(tokens, open));
      const values = inner.filter(
        (t) => !isPunct(t, ",") && !isPunct(t, "[") && !isPunct(t, "]") && !isWord(t, "array"),
      );
      if (values.length > 0 && values.every((t) => t.kind === "string")) return true;
    }
  }
  return false;
}
