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
  const out: DoBlockExpansion = { statements: [], dynamic: false };
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
  for (const tk of inner) {
    if (tk.length === 0) continue;
    if (loop) {
      inLoop(tk);
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
  if (loop) out.dynamic = true;
  return out;

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
