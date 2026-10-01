import { identOf, qualifiedKey, readQualifiedName } from "./sql-columns.js";
import { groupEnd, isPunct, isWord, splitSqlStatements, type Token } from "./sql-lexer.js";

/**
 * Columns a function body fills straight from sign-up metadata: `new.raw_user_meta_data ->> 'role'`
 * in an INSERT (VALUES or SELECT list) or an UPDATE ... SET, directly or through a local variable.
 * Whoever calls `supabase.auth.signUp({ options: { data } })` chooses that value.
 *
 * Unguarded shapes only: the bare read, `coalesce(<read>, <default>)`, a cast (`(<read>)::user_role`),
 * `nullif`, `trim`/`lower`, and `array[<read>]`. A CASE (the allow-list with a safe ELSE) or an IN test
 * makes the value a choice among the author's literals, so it does not count. Table keys are spelled
 * like `RlsTable.table`; column names lowercase. Text matching over the lexer's tokens; never throws.
 */
export function metadataCopiesIn(
  body: string,
): Array<{ table: string; column: string; key: string }> {
  if (!/raw_user_meta_data/i.test(body)) return [];
  const statements = splitSqlStatements(body).map((s) => s.tokens);
  // Local variables assigned from metadata: `v_role := new.raw_user_meta_data ->> 'role';`
  // or `select new.raw_user_meta_data ->> 'role' into v_role`.
  const vars = new Map<string, string>();
  for (const tk of statements) {
    for (let i = 1; i < tk.length; i += 1) {
      const colon = tk[i];
      const eq = tk[i + 1];
      if (colon?.raw !== ":" || eq?.raw !== "=" || eq.start !== colon.end) continue;
      // `v_role := ...`, or a declaration `v_meta jsonb := ...` where the type sits in between.
      let j = i - 1;
      while (j >= 0 && tk[j] !== undefined && TYPE_PART(tk[j] as Token)) j -= 1;
      const declared =
        j < 0 || isWord(tk[j], "declare") || isWord(tk[j], "begin")
          ? identOf(tk[j + 1])?.toLowerCase()
          : undefined;
      const target = declared ?? identOf(tk[i - 1])?.toLowerCase();
      if (!target) continue;
      const expr = tk.slice(i + 2);
      // `v_meta := new.raw_user_meta_data`: the variable holds the whole metadata object.
      if (isWholeMetadata(expr)) {
        vars.set(target, WHOLE);
        continue;
      }
      const key = unguardedRead(expr, vars);
      if (key !== null) vars.set(target, key);
    }
  }
  const out: Array<{ table: string; column: string; key: string }> = [];
  const add = (table: string, column: string, key: string): void => {
    if (!out.some((x) => x.table === table && x.column === column))
      out.push({ table, column, key });
  };
  for (const tk of statements) {
    for (let i = 0; i < tk.length; i += 1) {
      if (isWord(tk[i], "insert") && isWord(tk[i + 1], "into")) {
        const rel = readQualifiedName(tk, i + 2);
        if (rel === null || !isPunct(tk[rel.next], "(")) continue;
        const close = groupEnd(tk, rel.next);
        const columns = splitTop(tk.slice(rel.next + 1, close)).map(
          (c) => identOf(c[0])?.toLowerCase() ?? "",
        );
        let values: Token[][] = [];
        if (isWord(tk[close + 1], "values") && isPunct(tk[close + 2], "(")) {
          values = splitTop(tk.slice(close + 3, groupEnd(tk, close + 2)));
        } else if (isWord(tk[close + 1], "select")) {
          values = splitTop(tk.slice(close + 2, endOfSelectList(tk, close + 2)));
        }
        columns.forEach((column, n) => {
          const expr = values[n];
          if (!column || expr === undefined) return;
          const key = unguardedRead(expr, vars);
          if (key !== null) add(qualifiedKey(rel), column, key);
        });
        i = close;
      } else if (isWord(tk[i], "update")) {
        const rel = readQualifiedName(tk, i + 1);
        if (rel === null || !isWord(tk[rel.next], "set")) continue;
        const end = findTop(tk, rel.next + 1, ["where", "returning", "from"]);
        for (const part of splitTop(tk.slice(rel.next + 1, end))) {
          const column = identOf(part[0])?.toLowerCase();
          if (!column || part[1]?.raw !== "=") continue;
          const key = unguardedRead(part.slice(2), vars);
          if (key !== null) add(qualifiedKey(rel), column, key);
        }
      }
    }
  }
  return out;
}

function TYPE_PART(t: Token): boolean {
  if (isWord(t, "declare") || isWord(t, "begin")) return false;
  return (
    t.kind === "word" ||
    t.kind === "ident" ||
    t.kind === "number" ||
    isPunct(t, ".") ||
    isPunct(t, "[") ||
    isPunct(t, "]") ||
    isPunct(t, "(") ||
    isPunct(t, ")") ||
    isPunct(t, ",")
  );
}

/** Marks a variable that holds the whole metadata object rather than one key of it. */
const WHOLE = "\u0000whole";

function isWholeMetadata(expr: readonly Token[]): boolean {
  const names = expr.filter((t) => !isPunct(t, "(") && !isPunct(t, ")"));
  const last = names[names.length - 1];
  return (
    identOf(last)?.toLowerCase() === "raw_user_meta_data" &&
    names.every((t) => isPunct(t, ".") || t.kind === "word" || t.kind === "ident") &&
    names.length <= 3
  );
}

const PASS_THROUGH = new Set(["coalesce", "nullif", "trim", "lower", "upper", "btrim"]);

/**
 * The metadata key an expression passes through unchanged, or null. `coalesce(a, b)` passes the
 * first argument's key; any CASE or IN inside means the author chose among fixed values.
 */
function unguardedRead(expr: readonly Token[], vars: ReadonlyMap<string, string>): string | null {
  if (expr.some((t) => isWord(t, "case") || isWord(t, "in") || isWord(t, "when"))) return null;
  let tk = [...expr];
  for (let guard = 0; guard < 8; guard += 1) {
    // Strip a trailing cast: `... ::public.user_role`, `::text[]`.
    const cast = tk.findIndex((t, i) => isPunct(t, "::") && depthAt(tk, i) === 0);
    if (cast > 0) tk = tk.slice(0, cast);
    const first = tk[0];
    if (isPunct(first, "(") && groupEnd(tk, 0) === tk.length - 1) {
      tk = tk.slice(1, -1);
      continue;
    }
    if (isWord(first, "array") && isPunct(tk[1], "[")) {
      tk = tk.slice(2, groupEnd(tk, 1));
      continue;
    }
    if (first?.kind === "word" && isWord(first, "coalesce") && isPunct(tk[1], "(")) {
      // coalesce(app_meta ->> 'role', user_meta ->> 'role', 'default'): any argument the client
      // controls can be the one that wins.
      for (const arg of splitTop(tk.slice(2, groupEnd(tk, 1)))) {
        const key = unguardedRead(arg, vars);
        if (key !== null) return key;
      }
      return null;
    }
    if (first?.kind === "word" && PASS_THROUGH.has(first.value) && isPunct(tk[1], "(")) {
      const inner = splitTop(tk.slice(2, groupEnd(tk, 1)));
      tk = inner[0] ?? [];
      continue;
    }
    break;
  }
  // new.raw_user_meta_data ->> 'role'   (or -> 'role', or raw_user_meta_data ->> 'role')
  const at = tk.findIndex((t) => identOf(t)?.toLowerCase() === "raw_user_meta_data");
  if (at >= 0) {
    const op = tk[at + 1];
    const key = tk[at + 2];
    const rest = tk.slice(at + 3);
    if (op?.kind === "op" && (op.raw === "->>" || op.raw === "->") && key?.kind === "string")
      return rest.length === 0 ? key.value.toLowerCase() : null;
    return null;
  }
  if (tk.length === 1) {
    const name = identOf(tk[0])?.toLowerCase();
    const held = name ? vars.get(name) : undefined;
    return held === undefined || held === WHOLE ? null : held;
  }
  // v_meta ->> 'user_type', where v_meta holds the whole metadata object.
  const holder = identOf(tk[0])?.toLowerCase();
  const op = tk[1];
  if (
    holder !== undefined &&
    vars.get(holder) === WHOLE &&
    op?.kind === "op" &&
    (op.raw === "->>" || op.raw === "->") &&
    tk[2]?.kind === "string" &&
    tk.length === 3
  )
    return tk[2].value.toLowerCase();
  return null;
}

function depthAt(tk: readonly Token[], at: number): number {
  let depth = 0;
  for (let i = 0; i < at; i += 1) {
    if (isPunct(tk[i], "(") || isPunct(tk[i], "[")) depth += 1;
    else if (isPunct(tk[i], ")") || isPunct(tk[i], "]")) depth -= 1;
  }
  return depth;
}

function splitTop(tokens: readonly Token[]): Token[][] {
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

function findTop(tk: readonly Token[], from: number, words: readonly string[]): number {
  let depth = 0;
  for (let i = from; i < tk.length; i += 1) {
    const t = tk[i];
    if (isPunct(t, "(")) depth += 1;
    else if (isPunct(t, ")")) depth -= 1;
    else if (depth === 0 && t?.kind === "word" && words.includes(t.value)) return i;
  }
  return tk.length;
}

function endOfSelectList(tk: readonly Token[], from: number): number {
  return findTop(tk, from, ["from", "on", "where", "returning"]);
}
