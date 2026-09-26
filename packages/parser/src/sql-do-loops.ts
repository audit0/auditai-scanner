import { identOf } from "./sql-columns.js";
import {
  findWord,
  groupInner,
  isPunct,
  isWord,
  type SqlStatement,
  splitSqlStatements,
  splitTopLevelTokens,
  type Token,
} from "./sql-lexer.js";

/**
 * DO blocks that apply one statement to a literal list of names:
 *
 *   do $$ declare t text; begin
 *     foreach t in array array['job_queue', 'send_ledger'] loop
 *       execute format('alter table public.%I enable row level security', t);
 *       execute format('create policy tenant_%s on public.%I for all using (...)', t, t);
 *       execute format('revoke all on public.%I from anon', t);
 *     end loop;
 *   end $$;
 *
 * The loop is unrolled: every `execute format(...)` (or `execute '<sql>'`) in its body becomes one
 * plain statement per element, with `%I`, `%s` and `%L` substituted the way Postgres does, so the
 * regular statement handlers see `alter table public.job_queue enable row level security`. Only
 * literal lists are followed: `array[...]` of string literals, `select unnest(array[...])`, and
 * `(values ('a'), ('b'))`. A loop over a query (`for f in select ... from pg_proc loop`), an EXECUTE
 * built from expressions, or an EXECUTE under an IF is dynamic SQL the scanner cannot evaluate;
 * such blocks are reported as dynamic so the caller can warn once per file.
 */
export interface DoBlockExpansion {
  statements: SqlStatement[];
  /** The block also runs SQL the expansion could not follow. */
  dynamic: boolean;
  /**
   * Loops over every SECURITY DEFINER function of one schema (see `functionCatalogLoop`). Which
   * functions exist is the model's knowledge, not the block's, so the caller runs each one against
   * the functions it knows at that point, with `renderFunctionSweep`.
   */
  functionSweeps: FunctionSweep[];
}

/**
 * `for fn in select p.oid::regprocedure from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 *  where n.nspname = 'public' and p.prosecdef loop execute format('revoke ... on function %s ...',
 *  fn.x); end loop;` — a privilege statement for every SECURITY DEFINER function of a schema.
 */
export interface FunctionSweep {
  schema: string;
  /** How many of the block's expanded statements run before the loop. */
  before: number;
  variable: string;
  /** The loop's EXECUTE statements, each rendering one GRANT or REVOKE. */
  body: Token[][];
}

interface Placeholder {
  kind: "I" | "s" | "L";
  /** 0-based argument index. */
  arg: number;
  start: number;
  end: number;
}

/** `%I`, `%s`, `%L`, positional `%2$I`, and `%%`; anything else is not a format string we support. */
function placeholders(fmt: string): Placeholder[] | null {
  const out: Placeholder[] = [];
  let next = 0;
  for (let i = 0; i < fmt.length; i += 1) {
    if (fmt.charAt(i) !== "%") continue;
    const rest = fmt.slice(i + 1);
    if (rest.startsWith("%")) {
      out.push({ kind: "s", arg: -1, start: i, end: i + 2 });
      i += 1;
      continue;
    }
    const m = /^(?:(\d+)\$)?([IsL])/.exec(rest);
    if (!m) return null;
    const arg = m[1] !== undefined ? Number(m[1]) - 1 : next;
    next = arg + 1;
    out.push({ kind: m[2] as Placeholder["kind"], arg, start: i, end: i + 1 + m[0].length });
    i += m[0].length;
  }
  return out;
}

function quoteIdent(v: string): string {
  return /^[a-z_][a-z0-9_]*$/.test(v) ? v : `"${v.replace(/"/g, '""')}"`;
}

function render(fmt: string, args: readonly string[]): string | null {
  const ph = placeholders(fmt);
  if (ph === null) return null;
  let out = "";
  let from = 0;
  for (const p of ph) {
    out += fmt.slice(from, p.start);
    from = p.end;
    if (p.arg < 0) {
      out += "%";
      continue;
    }
    const v = args[p.arg];
    if (v === undefined) return null;
    out += p.kind === "I" ? quoteIdent(v) : p.kind === "L" ? `'${v.replace(/'/g, "''")}'` : v;
  }
  return out + fmt.slice(from);
}

/** A literal argument of format(): a string, the loop variable (or a field of it), else null. */
function literalArg(
  part: readonly Token[],
  loopVar: string | null,
  element: string | null,
): string | null {
  const first = part[0];
  if (!first) return null;
  if (part.length === 1 && first.kind === "string") return first.value;
  if (loopVar === null || element === null) return null;
  const name = identOf(first);
  if (name === null || name.toLowerCase() !== loopVar) return null;
  if (part.length === 1) return element;
  // `r.column1` for a VALUES row, `t.name` for a record loop over one column.
  if (part.length === 3 && isPunct(part[1], ".") && identOf(part[2]) !== null) return element;
  return null;
}

/** The SQL an `execute` statement runs for one element, or null when it is not a literal. */
function executedSql(
  tk: readonly Token[],
  loopVar: string | null,
  element: string | null,
): string | null {
  if (!isWord(tk[0], "execute")) return null;
  const a = tk[1];
  if (a?.kind === "string" && tk.length === 2) return a.value;
  if (!isWord(a, "format") || !isPunct(tk[2], "(")) return null;
  const parts = splitTopLevelTokens(groupInner(tk, 2));
  const fmtTok = parts[0]?.[0];
  if (!fmtTok || parts[0]?.length !== 1 || fmtTok.kind !== "string") return null;
  const args: string[] = [];
  for (const part of parts.slice(1)) {
    const v = literalArg(part, loopVar, element);
    if (v === null) return null;
    args.push(v);
  }
  return render(fmtTok.value, args);
}

/** String literals of `array['a', 'b']`, `unnest(array[...])`, `(values ('a'), ('b'))`; null when anything is not a literal. */
function literalElements(expr: readonly Token[]): string[] | null {
  const arrayAt = expr.findIndex((t, i) => isWord(t, "array") && isPunct(expr[i + 1], "["));
  if (arrayAt >= 0) {
    const out: string[] = [];
    for (const part of splitTopLevelTokens(groupInner(expr, arrayAt + 1))) {
      const t = part[0];
      if (!t || part.length !== 1 || t.kind !== "string") return null;
      out.push(t.value);
    }
    return out;
  }
  const valuesAt = expr.findIndex((t) => isWord(t, "values"));
  if (valuesAt >= 0) {
    const out: string[] = [];
    let rows = expr.slice(valuesAt + 1);
    // `(values (...), (...))` leaves a closing parenthesis behind; `... ) as v(x)` keeps a tail we skip.
    const close = rows.findIndex((t, i) => isPunct(t, ")") && depthAt(rows, i) < 0);
    if (close >= 0) rows = rows.slice(0, close);
    for (const part of splitTopLevelTokens(rows)) {
      if (!isPunct(part[0], "(")) return null;
      const inner = groupInner(part, 0);
      const t = inner[0];
      if (!t || inner.length !== 1 || t.kind !== "string") return null;
      out.push(t.value);
    }
    return out;
  }
  return null;
}

/** Parenthesis depth just before token `i` (negative when a group closes that was opened earlier). */
function depthAt(tokens: readonly Token[], i: number): number {
  let depth = 0;
  for (let j = 0; j < i; j += 1) {
    if (isPunct(tokens[j], "(") || isPunct(tokens[j], "[")) depth += 1;
    else if (isPunct(tokens[j], ")") || isPunct(tokens[j], "]")) depth -= 1;
  }
  return depth;
}

interface LoopHeader {
  variable: string;
  elements: string[] | null;
  /** Tokens after `loop` on the header's own statement. */
  rest: Token[];
}

/** Literal arrays bound in the DECLARE section: `v_tables text[] := array['a', 'b']`. */
type DeclaredLists = ReadonlyMap<string, string[]>;

/** `foreach t in array <expr> loop ...` / `for t in <expr> loop ...`; null when the statement is not a loop. */
function loopHeader(tk: readonly Token[], declared: DeclaredLists): LoopHeader | null {
  const foreach = isWord(tk[0], "foreach");
  if (!foreach && !isWord(tk[0], "for")) return null;
  const variable = identOf(tk[1])?.toLowerCase();
  if (variable === undefined || !isWord(tk[2], "in")) return null;
  const loopAt = findWord(tk, 3, "loop");
  if (loopAt < 0) return null;
  let from = 3;
  if (foreach && isWord(tk[from], "array")) from += 1;
  if (isWord(tk[from], "reverse")) return { variable, elements: null, rest: [] };
  const expr = tk.slice(from, loopAt);
  const rest = tk.slice(loopAt + 1);
  const name = expr.length === 1 ? identOf(expr[0])?.toLowerCase() : undefined;
  if (name !== undefined) return { variable, elements: declared.get(name) ?? null, rest };
  // `for i in 1..10 loop` is an integer range, not a list of names.
  const elements = expr.some((t) => t.kind === "op" && t.raw === "..")
    ? null
    : literalElements(expr);
  return { variable, elements, rest };
}

/**
 * The one query loop worth following: the signature lookup that a REVOKE sweep wraps around a literal
 * list of function names.
 *
 *   foreach fn in array names loop
 *     for sig in select format('public.%I(%s)', p.proname, pg_get_function_identity_arguments(p.oid))
 *                from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 *                where n.nspname = 'public' and p.proname = fn and p.prosecdef loop
 *       execute format('revoke execute on function %s from public, anon, authenticated', sig);
 *
 * Every row it can yield is a function whose name is the outer element, so the inner variable is
 * `<schema>.<name>` and the body can be unrolled. The shape is matched exactly — the select must name
 * `pg_proc`, must restrict `prosecdef`, must compare `proname` with the outer variable, and must fix
 * the schema to a literal — because anything looser is a query this parser cannot evaluate. A GRANT or
 * REVOKE written without an argument list applies to every overload of the name, which is what the
 * `prosecdef` restriction means here anyway.
 */
function signatureLoop(
  tk: readonly Token[],
  outerVar: string,
): { variable: string; schema: string; rest: Token[] } | null {
  if (!isWord(tk[0], "for")) return null;
  const variable = identOf(tk[1])?.toLowerCase();
  if (variable === undefined || !isWord(tk[2], "in")) return null;
  const loopAt = findWord(tk, 3, "loop");
  if (loopAt < 0) return null;
  const expr = tk.slice(3, loopAt);
  if (!expr.some((t) => isWord(t, "pg_proc")) || !expr.some((t) => isWord(t, "prosecdef")))
    return null;
  let schema: string | null = null;
  let namesOuter = false;
  for (let i = 0; i < expr.length; i++) {
    const word = identOf(expr[i])?.toLowerCase();
    if (word === undefined) continue;
    const eq = expr[i + 1];
    if (!(eq?.kind === "op" && eq.raw === "=")) continue;
    const value = expr[i + 2];
    if (word === "nspname" && value?.kind === "string") schema = value.value;
    if (word === "proname" && identOf(value)?.toLowerCase() === outerVar) namesOuter = true;
  }
  if (schema === null || !namesOuter) return null;
  return { variable, schema, rest: tk.slice(loopAt + 1) };
}

/**
 * The catalog loop of `FunctionSweep`, matched exactly: the select list is the function's signature
 * (`oid::regprocedure`), the only relations are `pg_proc` and `pg_namespace`, and the WHERE clause is
 * a conjunction of a literal schema, `prosecdef`, the join condition and at most `prokind = 'f'`.
 * Anything else (a name filter, NOT, EXISTS, IN, OR, a LIMIT) selects a subset this parser cannot
 * evaluate, so the loop stays dynamic SQL.
 */
function functionCatalogLoop(
  tk: readonly Token[],
): { variable: string; schema: string; field: string; rest: Token[] } | null {
  if (!isWord(tk[0], "for")) return null;
  const variable = identOf(tk[1])?.toLowerCase();
  if (variable === undefined || !isWord(tk[2], "in")) return null;
  const loopAt = findWord(tk, 3, "loop");
  if (loopAt < 0) return null;
  const q = tk.slice(3, loopAt);
  if (!isWord(q[0], "select")) return null;
  const fromAt = findWord(q, 1, "from");
  const whereAt = findWord(q, 1, "where");
  if (fromAt < 0 || whereAt < fromAt) return null;
  const text = (part: readonly Token[]): string =>
    part
      .map((t) => t.raw)
      .join(" ")
      .toLowerCase();
  // The select list is the signature: `oid::regprocedure`, optionally cast to text, optionally named.
  // The record field the body may read is that name, or `oid` without one.
  const select = /^(?:(\w+) \. )?oid :: regprocedure(?: :: text)?(?: (?:as )?(\w+))?$/.exec(
    text(q.slice(1, fromAt)),
  );
  if (!select) return null;
  const field = select[2] ?? "oid";
  // Exactly pg_proc joined to pg_namespace on the namespace, in either order or as a comma join with
  // the condition in WHERE; nothing else in FROM, so no ON clause can filter.
  const rel = "(?:pg_catalog \\. )?(?:pg_proc|pg_namespace)(?: (?:as )?\\w+)?";
  const on = "(?:\\w+ \\. )?(?:oid = (?:\\w+ \\. )?pronamespace|pronamespace = (?:\\w+ \\. )?oid)";
  const fromText = text(q.slice(fromAt + 1, whereAt));
  const relations = fromText.match(/pg_proc|pg_namespace/g) ?? [];
  if (relations.length !== 2 || relations[0] === relations[1]) return null;
  if (
    !new RegExp(`^${rel} (?:inner )?join ${rel} on ${on}$`).test(fromText) &&
    !new RegExp(`^${rel} , ${rel}$`).test(fromText)
  )
    return null;
  const where = q.slice(whereAt + 1);
  const banned = [
    "or",
    "not",
    "exists",
    "in",
    "like",
    "ilike",
    "select",
    "limit",
    "offset",
    "union",
  ];
  if (where.some((t) => t.kind === "word" && banned.includes(t.value))) return null;
  let schema: string | null = null;
  let secdef = false;
  let conjunct: Token[] = [];
  const conjuncts: Token[][] = [];
  for (const [i, t] of where.entries()) {
    if (isWord(t, "and") && depthAt(where, i) === 0) {
      conjuncts.push(conjunct);
      conjunct = [];
    } else conjunct.push(t);
  }
  conjuncts.push(conjunct);
  for (const c of conjuncts) {
    const x = text(c);
    const last = c[c.length - 1];
    // Postgres compares nspname case-sensitively, so the literal is kept as written.
    if (/^(?:\w+ \. )?nspname = \S+$/.test(x) && last?.kind === "string" && c.length <= 5) {
      schema = last.value;
    } else if (/^(?:\w+ \. )?prosecdef(?: = true| is true)?$/.test(x)) secdef = true;
    else if (new RegExp(`^${on}$`).test(x)) continue;
    else if (/^(?:\w+ \. )?prokind = 'f'$/.test(x)) continue;
    else return null;
  }
  if (schema === null || !secdef) return null;
  return { variable, schema, field, rest: tk.slice(loopAt + 1) };
}

/** Statements a block may hold next to a `FunctionSweep`: declarations, notices and its END. */
function sweepCompatible(tk: readonly Token[]): boolean {
  if (isWord(tk[0], "declare")) return true;
  if (isWord(tk[0], "end") && tk.length <= 2) return true;
  if (isWord(tk[0], "raise") && ["notice", "info", "log", "debug"].some((w) => isWord(tk[1], w)))
    return true;
  // `r record;` or `n text;`, a further declaration in the DECLARE section.
  return tk.length === 2 && identOf(tk[0]) !== null && tk[1]?.kind === "word";
}

/**
 * Plain GRANT statements anywhere in a DO block — at the top, after THEN or ELSE, in a nested BEGIN,
 * in an exception handler. They are applied whether or not the branch runs: reading a grant can only
 * report more, never hide a finding, while dropping one can hide a function a later block re-opened.
 */
export function grantsInDoBlock(stmt: SqlStatement): SqlStatement[] {
  const body = stmt.tokens.find((t) => t.kind === "string");
  if (!body || !isWord(stmt.tokens[0], "do")) return [];
  const out: SqlStatement[] = [];
  for (const inner of splitSqlStatements(body.value)) {
    const tk = inner.tokens;
    const at = tk.findIndex(
      (t, i) =>
        isWord(t, "grant") &&
        (i === 0 ||
          ["then", "else", "begin", "loop", "others"].some((w) => isWord(tk[i - 1], w)) ||
          isPunct(tk[i - 1], ";")),
    );
    if (at < 0) continue;
    const tokens = tk.slice(at);
    out.push({ ...inner, tokens, line: stmt.line });
  }
  return out;
}

/** A signature as `oid::regprocedure` prints it, for `renderFunctionSweep`. */
export function sweepSignature(schema: string, name: string, args: string | null): string {
  return `${quoteIdent(schema)}.${quoteIdent(name)}(${args ?? ""})`;
}

/**
 * The GRANT and REVOKE statements a `FunctionSweep` runs for one function, or null when any of its
 * EXECUTEs renders something else.
 */
export function renderFunctionSweep(
  sweep: FunctionSweep,
  signature: string,
  line: number,
): SqlStatement[] | null {
  const out: SqlStatement[] = [];
  for (const tk of sweep.body) {
    const sql = executedSql(tk, sweep.variable, signature);
    if (sql === null) return null;
    for (const st of splitSqlStatements(sql)) {
      if (!isWord(st.tokens[0], "grant") && !isWord(st.tokens[0], "revoke")) return null;
      out.push({ ...st, line });
    }
  }
  return out;
}

/** `declare v_tables text[] := array['a', 'b'];` (also `default`, `constant`): the literal list a loop may iterate. */
function declaredList(tk: readonly Token[]): [string, string[]] | null {
  let i = 0;
  if (isWord(tk[i], "declare")) i += 1;
  const name = identOf(tk[i])?.toLowerCase();
  if (name === undefined) return null;
  // The lexer reads `:=` as the two operators `:` and `=`.
  const assign = tk.findIndex(
    (t, j) =>
      j > i &&
      ((t.kind === "op" && t.raw === ":" && tk[j + 1]?.raw === "=") || isWord(t, "default")),
  );
  if (assign < 0) return null;
  const elements = literalElements(tk.slice(assign + (isWord(tk[assign], "default") ? 1 : 2)));
  return elements === null ? null : [name, elements];
}

function stripBegin(tk: readonly Token[]): Token[] {
  let i = 0;
  while (isWord(tk[i], "begin")) i += 1;
  return tk.slice(i);
}

/** PL/pgSQL control statements that make what follows conditional. */
function conditionalDelta(tk: readonly Token[]): number {
  if ((isWord(tk[0], "if") && findWord(tk, 1, "then") >= 0) || isWord(tk[0], "case")) return 1;
  if (isWord(tk[0], "end") && (isWord(tk[1], "if") || isWord(tk[1], "case"))) return -1;
  return 0;
}

/**
 * Unrolls the literal loops (and plain literal EXECUTEs) of a DO block into ordinary statements.
 * `stmt` is the DO statement; its dollar-quoted body is the block.
 */
export function expandDoBlock(stmt: SqlStatement): DoBlockExpansion {
  const body = stmt.tokens.find((t) => t.kind === "string");
  const out: DoBlockExpansion = { statements: [], dynamic: false, functionSweeps: [] };
  if (!body || !isWord(stmt.tokens[0], "do")) return out;
  const inner = splitSqlStatements(body.value).map((s) => stripBegin(s.tokens));
  const emit = (sql: string | null): void => {
    if (sql === null) {
      out.dynamic = true;
      return;
    }
    for (const s of splitSqlStatements(sql)) out.statements.push({ ...s, line: stmt.line });
  };
  const declared = new Map<string, string[]>();
  for (const tk of inner) {
    const d = declaredList(tk);
    if (d) declared.set(d[0], d[1]);
  }
  let conditional = 0;
  let loop: LoopHeader | null = null;
  const bodyStatements: Token[][] = [];
  let sigLoop: { variable: string; schema: string; rest: Token[] } | null = null;
  const sigBody: Token[][] = [];
  // Anything but declarations, the loop, a notice and END (a GRANT after the loop, an IF, a nested
  // block, a DROP) may change what the loop did, and the rest of the block is not modelled here.
  let otherStatements = false;
  let catalog: {
    variable: string;
    schema: string;
    field: string;
    body: Token[][];
    valid: boolean;
  } | null = null;
  for (const tk of inner) {
    if (tk.length === 0) continue;
    if (catalog) {
      inCatalog(tk);
      continue;
    }
    if (loop) {
      inLoop(tk);
      continue;
    }
    const cat = conditional === 0 ? functionCatalogLoop(tk) : null;
    if (!cat && !sweepCompatible(tk)) otherStatements = true;
    if (cat) {
      catalog = {
        variable: cat.variable,
        schema: cat.schema,
        field: cat.field,
        body: [],
        valid: true,
      };
      if (cat.rest.length > 0) inCatalog(cat.rest);
      continue;
    }
    const header = loopHeader(tk, declared);
    if (header) {
      loop = header;
      if (conditional > 0) loop.elements = null;
      // The header and its first body statement share one statement when no semicolon separates
      // them (`foreach t in array names loop execute ...`), so the tail goes through the same path.
      if (header.rest.length > 0) inLoop(header.rest);
      continue;
    }
    conditional = Math.max(0, conditional + conditionalDelta(tk));
    if (isWord(tk[0], "execute")) emit(conditional > 0 ? null : executedSql(tk, null, null));
  }
  if (loop || catalog) out.dynamic = true;
  // An exception handler may swallow a failed statement, so what the block did is not known.
  if (
    out.functionSweeps.length > 0 &&
    (otherStatements || inner.some((tk) => isWord(tk[0], "exception")))
  ) {
    out.functionSweeps = [];
    out.dynamic = true;
  }
  return out;

  function inCatalog(tk: Token[]): void {
    if (!catalog) return;
    if (isWord(tk[0], "end") && isWord(tk[1], "loop")) {
      const sweep: FunctionSweep = {
        schema: catalog.schema,
        before: out.statements.length,
        variable: catalog.variable,
        body: catalog.body,
      };
      const probe = renderFunctionSweep(sweep, sweepSignature(catalog.schema, "f", ""), stmt.line);
      if (catalog.valid && catalog.body.length > 0 && probe !== null)
        out.functionSweeps.push(sweep);
      else out.dynamic = true;
      catalog = null;
      return;
    }
    // Only privilege statements (and notices) may run in the loop body, and the record is read only
    // through the signature column: `fn.x` for another name fails in Postgres, `fn` alone renders the
    // whole row.
    const readsRecord = tk.every(
      (t, i) =>
        identOf(t)?.toLowerCase() !== catalog?.variable ||
        (isPunct(tk[i + 1], ".") && identOf(tk[i + 2])?.toLowerCase() === catalog?.field),
    );
    const quietRaise =
      isWord(tk[0], "raise") &&
      ["notice", "info", "log", "debug", "warning"].some((w) => isWord(tk[1], w));
    if (isWord(tk[0], "execute") && readsRecord) catalog.body.push(tk);
    else if (!quietRaise) catalog.valid = false;
  }

  function inLoop(tk: Token[]): void {
    if (!loop) return;
    const ends = isWord(tk[0], "end") && isWord(tk[1], "loop");
    // The inner loop closes first: its `end loop` is not the outer one's.
    if (sigLoop) {
      if (ends) {
        runSignatureLoop(loop, sigLoop, sigBody, emit);
        sigLoop = null;
        sigBody.length = 0;
        return;
      }
      if (loopHeader(tk, declared)) loop.elements = null;
      sigBody.push(tk);
      return;
    }
    if (ends) {
      if (loop.elements === null) out.dynamic = true;
      else runLoop(loop, bodyStatements, emit);
      loop = null;
      bodyStatements.length = 0;
      return;
    }
    const sig = loop.elements === null ? null : signatureLoop(tk, loop.variable);
    if (sig) {
      sigLoop = sig;
      if (sig.rest.length > 0) sigBody.push(sig.rest);
      return;
    }
    if (loopHeader(tk, declared)) {
      // A nested loop is more than we follow: the outer body is not unrolled.
      loop.elements = null;
    }
    bodyStatements.push(tk);
  }
}

/** The inner body, once per name of the outer literal list, with the signature variable bound. */
function runSignatureLoop(
  loop: LoopHeader,
  sig: { variable: string; schema: string },
  body: readonly Token[][],
  emit: (sql: string | null) => void,
): void {
  const elements = loop.elements ?? [];
  let conditional = 0;
  for (const tk of body) {
    conditional = Math.max(0, conditional + conditionalDelta(tk));
    if (!isWord(tk[0], "execute")) continue;
    if (conditional > 0) {
      emit(null);
      continue;
    }
    for (const element of elements) emit(executedSql(tk, sig.variable, `${sig.schema}.${element}`));
  }
}

function runLoop(
  loop: LoopHeader,
  body: readonly Token[][],
  emit: (sql: string | null) => void,
): void {
  const elements = loop.elements ?? [];
  let conditional = 0;
  for (const tk of body) {
    conditional = Math.max(0, conditional + conditionalDelta(tk));
    if (!isWord(tk[0], "execute")) continue;
    if (conditional > 0) {
      emit(null);
      continue;
    }
    for (const element of elements) emit(executedSql(tk, loop.variable, element));
  }
}
