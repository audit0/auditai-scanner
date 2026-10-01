import { qualifiedKey, readQualifiedName } from "./sql-columns.js";
import { groupEnd, isPunct, isWord, splitSqlStatements, type Token } from "./sql-lexer.js";

/**
 * Columns of the caller's own row that SQL treats as a privilege: a function body or a policy
 * expression that reads `<column>` from `<table>` in a query filtered by the caller's identity and
 * compares it with an admin-like literal, or selects a role-named column of that row.
 *
 *   exists (select 1 from profiles where id = auth.uid() and role = 'admin')
 *   (select role from public.profiles where id = auth.uid()) = 'admin'
 *   select coalesce(user_types, '{}') @> array['admin'] from profiles where id = auth.uid()
 *   'admin' = any (select roles from members where user_id = auth.uid())
 *
 * Whether the user can rewrite that column is the rules' question. Table keys are spelled like
 * `RlsTable.table`; column names lowercase. Text matching over the lexer's tokens; never throws.
 */
export function roleColumnsIn(text: string): Array<{ table: string; column: string }> {
  if (!IDENTITY_TEXT.test(text)) return [];
  const out: Array<{ table: string; column: string }> = [];
  const add = (table: string, column: string): void => {
    if (!out.some((x) => x.table === table && x.column === column)) out.push({ table, column });
  };
  for (const s of splitSqlStatements(text)) {
    const tk = s.tokens;
    for (let i = 0; i < tk.length; i += 1) {
      if (!isWord(tk[i], "select")) continue;
      const [start, end] = enclosing(tk, i);
      const from = findWord(tk, i, end, "from");
      if (from < 0) continue;
      const rel = readQualifiedName(tk, from + 1);
      if (rel === null) continue;
      const table = qualifiedKey(rel);
      const alias = aliasAfter(tk, rel.next);
      if (!readsIdentity(tk, from, end) && !identityBefore(tk, start)) continue;
      // Form A: the comparison sits inside the query.
      for (let k = i + 1; k < end; k += 1) {
        // A nested query is judged on its own: its literals say nothing about this table's columns.
        if (isPunct(tk[k], "(") && isWord(tk[k + 1], "select")) {
          k = groupEnd(tk, k);
          continue;
        }
        const col = columnAt(tk, k, alias, table);
        if (col === null) continue;
        if (comparesWithRoleLiteral(tk, col.next) || literalAnyOf(tk, k)) add(table, col.name);
      }
      // Form B: the query selects one column of the caller's row.
      const selected = columnAt(tk, i + 1, alias, table);
      if (selected !== null && isWord(tk[selected.next], "from")) {
        const closed = isPunct(tk[start], "(") ? end : -1;
        const comparedOutside =
          closed >= 0 && (comparesWithRoleLiteral(tk, closed + 1) || literalAnyOf(tk, start));
        if (ROLE_COLUMN.test(selected.name) || comparedOutside) add(table, selected.name);
      }
    }
  }
  return out;
}

/**
 * Columns of the caller's own row that SQL treats as their tenant: a function body or a policy
 * expression that selects a tenant-named column from a query filtered by the caller's identity, or
 * compares such a column of that query's table with a column of another table.
 *
 *   select organisation_id from user_profiles where id = auth.uid()
 *   org_id in (select org_id from members where user_id = auth.uid())
 *   exists (select 1 from members m where m.org_id = projects.org_id and m.user_id = auth.uid())
 *
 * Whoever can write that column joins the tenant; whether a user can is the rules' question. Same
 * spelling as `roleColumnsIn`; never throws.
 */
export function scopeColumnsIn(text: string): Array<{ table: string; column: string }> {
  if (!IDENTITY_TEXT.test(text) || !TENANT_TEXT.test(text)) return [];
  const out: Array<{ table: string; column: string }> = [];
  const add = (table: string, column: string): void => {
    if (!out.some((x) => x.table === table && x.column === column)) out.push({ table, column });
  };
  for (const s of splitSqlStatements(text)) {
    const tk = s.tokens;
    for (let i = 0; i < tk.length; i += 1) {
      if (!isWord(tk[i], "select")) continue;
      const [start, end] = enclosing(tk, i);
      const from = findWord(tk, i, end, "from");
      if (from < 0) continue;
      const rel = readQualifiedName(tk, from + 1);
      if (rel === null) continue;
      const table = qualifiedKey(rel);
      const alias = aliasAfter(tk, rel.next);
      if (!readsIdentity(tk, from, end) && !identityBefore(tk, start)) continue;
      // The query selects the tenant column of the caller's row.
      const selected = columnAt(tk, i + 1, alias, table);
      if (
        selected !== null &&
        isWord(tk[selected.next], "from") &&
        TENANT_COLUMN.test(selected.name)
      )
        add(table, selected.name);
      // Or ties it to another table's row: `m.org_id = projects.org_id`.
      for (let k = from + 1; k < end; k += 1) {
        if (isPunct(tk[k], "(") && isWord(tk[k + 1], "select")) {
          k = groupEnd(tk, k);
          continue;
        }
        if (!isPunct(tk[k + 1], ".")) continue;
        const col = columnAt(tk, k, alias, table);
        if (col === null || !TENANT_COLUMN.test(col.name)) continue;
        const op = tk[col.next];
        if (op?.kind !== "op" || op.raw !== "=") continue;
        const other = tk[col.next + 1];
        const otherName =
          other?.kind === "word"
            ? other.value
            : other?.kind === "ident"
              ? other.value.toLowerCase()
              : "";
        if (otherName !== "" && otherName !== alias && isPunct(tk[col.next + 2], "."))
          add(table, col.name);
      }
    }
  }
  return out;
}

/**
 * Columns SQL decides on as what a user paid for or may spend: a function body or a policy that
 * reads an entitlement-named column (credits, balance, plan, tier, kyc status...) of `<table>` and
 * compares it, whatever the query filters on (the row may be picked by a parameter the caller
 * passes, `p_uid` or `p_tenant_id`).
 *
 *   select p.plan = 'plus' from profiles p where p.id = p_uid
 *   select credits into v_credits from profiles where id = p_user_id; if v_credits <= 0 then raise
 *   (select plan from tenants where id = p_tenant_id) <> 'free'
 *
 * Merely returning the column (`'plan', p.plan`) is not a decision. Whether the row's owner can
 * rewrite it is the rules' question. Same spelling as `roleColumnsIn`; never throws.
 */
export function entitlementColumnsIn(text: string): Array<{ table: string; column: string }> {
  if (!ENTITLEMENT_TEXT.test(text)) return [];
  const out: Array<{ table: string; column: string }> = [];
  const add = (table: string, column: string): void => {
    if (!out.some((x) => x.table === table && x.column === column)) out.push({ table, column });
  };
  const statements = splitSqlStatements(text);
  statements.forEach((s, si) => {
    const tk = s.tokens;
    for (let i = 0; i < tk.length; i += 1) {
      if (!isWord(tk[i], "select")) continue;
      const [start, end] = enclosing(tk, i);
      const from = findWord(tk, i, end, "from");
      if (from < 0) continue;
      const rel = readQualifiedName(tk, from + 1);
      if (rel === null) continue;
      const table = qualifiedKey(rel);
      const alias = aliasAfter(tk, rel.next);
      // Inside the query: `p.plan = 'plus'`, `credits > 0`.
      for (let k = i + 1; k < end; k += 1) {
        if (isPunct(tk[k], "(") && isWord(tk[k + 1], "select")) {
          k = groupEnd(tk, k);
          continue;
        }
        const col = columnAt(tk, k, alias, table);
        if (col === null || !ENTITLEMENT_COLUMN.test(col.name)) continue;
        if (comparedAt(tk, k, col.next)) add(table, col.name);
      }
      const selected = columnAt(tk, i + 1, alias, table);
      // `(select plan from tenants where ...) <> 'free'`.
      if (
        selected !== null &&
        ENTITLEMENT_COLUMN.test(selected.name) &&
        isPunct(tk[start], "(") &&
        comparedAt(tk, start, end + 1)
      )
        add(table, selected.name);
      // `select balance, total_used into v_balance, v_used from ...`, then `v_balance` decides.
      for (const { column, variable } of selectInto(tk, i, alias, table)) {
        if (!ENTITLEMENT_COLUMN.test(column)) continue;
        const later = [tk.slice(i + 1), ...statements.slice(si + 1).map((x) => x.tokens)];
        if (later.some((t) => variableDecides(t, variable))) add(table, column);
      }
    }
  });
  return out;
}

const ORDERING = new Set(["<", "<=", ">", ">="]);
const EQUALITY = new Set(["=", "<>", "!="]);

/** `'pro'`, `0`, `true`, `-1`, `'free'::text`. */
function literalAt(tk: readonly Token[], j: number): boolean {
  const t = tk[j];
  if (t?.kind === "op" && t.raw === "-") return tk[j + 1]?.kind === "number";
  return t?.kind === "string" || t?.kind === "number" || isWord(t, "true") || isWord(t, "false");
}

/** `('pro', 'team')`, `('pro'::plan_t)`: literals only, casts allowed. */
function literalList(tk: readonly Token[], open: number): boolean {
  const close = groupEnd(tk, open);
  let found = false;
  for (let j = open + 1; j < close; j += 1) {
    if (isPunct(tk[j], ",")) continue;
    if (isPunct(tk[j], "::")) {
      j += 1;
      continue;
    }
    if (!literalAt(tk, j)) return false;
    if (tk[j]?.kind === "op") j += 1;
    found = true;
  }
  return found;
}

/**
 * The value spanning tokens [k, next) is decided on: ordered against anything (`credits <= 0`,
 * `balance >= p_cost`), or tested for equality with a literal (`plan = 'plus'`, `tier in ('pro')`).
 * Equality with a parameter or another column is a search filter or a join (`p.plan = p_plan`).
 */
function comparedAt(tk: readonly Token[], k: number, next: number): boolean {
  const after = tk[next];
  const before = tk[k - 1];
  if (after?.kind === "op" && ORDERING.has(after.raw)) return true;
  if (before?.kind === "op" && ORDERING.has(before.raw)) return true;
  if (after?.kind === "op" && EQUALITY.has(after.raw) && literalAt(tk, next + 1)) return true;
  if (before?.kind === "op" && EQUALITY.has(before.raw) && literalAt(tk, k - 2)) return true;
  if (isWord(after, "in") && isPunct(tk[next + 1], "(")) return literalList(tk, next + 1);
  if (isWord(after, "not") && isWord(tk[next + 1], "in") && isPunct(tk[next + 2], "("))
    return literalList(tk, next + 2);
  return false;
}

/** `select a, b into x, y from ...` at `select` index i: the columns paired with the variables, by position. */
function selectInto(
  tk: readonly Token[],
  i: number,
  alias: string | null,
  table: string,
): Array<{ column: string; variable: string }> {
  const columns: Array<string | null> = [];
  let j = i + 1;
  for (;;) {
    const col = columnAt(tk, j, alias, table);
    columns.push(col?.name ?? null);
    // Skip the rest of this select item.
    let depth = 0;
    let k = col?.next ?? j;
    for (; k < tk.length; k += 1) {
      if (isPunct(tk[k], "(")) depth += 1;
      else if (isPunct(tk[k], ")")) depth -= 1;
      if (depth < 0) return [];
      if (depth === 0 && (isPunct(tk[k], ",") || isWord(tk[k], "into") || isWord(tk[k], "from")))
        break;
    }
    if (isPunct(tk[k], ",")) {
      j = k + 1;
      continue;
    }
    if (!isWord(tk[k], "into")) return [];
    j = k + 1;
    break;
  }
  if (isWord(tk[j], "strict")) j += 1;
  const out: Array<{ column: string; variable: string }> = [];
  for (let n = 0; n < columns.length; n += 1) {
    const v = tk[j];
    const variable =
      v?.kind === "word" ? v.value : v?.kind === "ident" ? v.value.toLowerCase() : "";
    if (variable === "" || isPunct(tk[j + 1], ".")) break;
    const column = columns[n];
    if (column) out.push({ column, variable });
    if (!isPunct(tk[j + 1], ",")) break;
    j += 2;
  }
  return out;
}

/** A token of `tk` compares variable `name`, an IF tests it bare, or a CASE picks by its literal values. */
function variableDecides(tk: readonly Token[], name: string): boolean {
  for (let j = 0; j < tk.length; j += 1) {
    const t = tk[j];
    const here = t?.kind === "word" ? t.value : t?.kind === "ident" ? t.value.toLowerCase() : "";
    if (here !== name || isPunct(tk[j - 1], ".")) continue;
    if (comparedAt(tk, j, j + 1)) return true;
    // A flag tested bare (`if v_premium then`, `if not v_paid then`); `if v is null` is not a decision.
    const prev = isWord(tk[j - 1], "not") ? tk[j - 2] : tk[j - 1];
    if ((isWord(prev, "if") || isWord(prev, "elsif")) && isWord(tk[j + 1], "then")) return true;
    // `case v_plan when 'free' then 1 when 'pro' then 3 end`.
    if (isWord(tk[j - 1], "case") && isWord(tk[j + 1], "when") && literalAt(tk, j + 2)) return true;
  }
  return false;
}

/**
 * Column names that hold what a user paid for or may spend: a balance, credits, points, a plan,
 * tier or subscription state, a premium flag, a usage counter, a KYC status. A match alone says
 * nothing; a rule also needs something that decides on it.
 */
export const ENTITLEMENT_COLUMN =
  /^(?:(?:wallet|account|credit|token|coin|point|gem)s?_?balance|balance|credits?|coins?|points|gems|(?:credits?|tokens?)_?(?:remaining|left|used)|remaining_?(?:credits|tokens)|plan|plan_?(?:id|type|tier|name|level)|(?:subscription|membership)(?:_?(?:tier|status|plan|level|type|active))?|tier|user_?tier|account_?tier|is_?premium|premium|is_?pro|is_?paid|has_?paid|is_?subscribed|payment_?status|quota|usage_?(?:count|limit)|trial_?ends?_?at|lifetime_?access|(?:plan|premium|pro|subscription)_?(?:expires|ends|until)(?:_?at)?|kyc_?(?:status|verified|level|approved))$/i;
const ENTITLEMENT_TEXT =
  /balance|credit|coin|point|gem|token|plan|tier|subscri|membership|premium|pro\b|paid|payment|quota|usage|trial|lifetime|kyc/i;

/** Column names that hold the tenant a row belongs to. */
export const TENANT_COLUMN =
  /^(?:org|orga?ni[sz]ation|tenant|company|companies|team|workspace|account|business|agency|salon|school|clinic|store|shop|branch|firm|practice|office|venue|restaurant|studio|gym|club|church|institution|department|merchant|household|family|community)_?id$/i;
const TENANT_TEXT =
  /(?:org|ni[sz]ation|tenant|company|team|workspace|account|business|agency|salon|school|clinic|store|shop|branch|firm|practice|office|venue|restaurant|studio|gym|club|church|institution|department|merchant|household|family|community)_?id/i;

const IDENTITY_TEXT = /auth\s*\.\s*(?:uid|jwt|email)\s*\(/i;
/** Values that name a privileged role. */
const ROLE_LITERAL =
  /^(?:admin|admins|administrator|super_?admin|superadmin|super-admin|superuser|owner|staff|moderator|manager|editor|support|operator|root|platform_admin|org_admin|system_admin)$/i;
/** Column names that hold a role by themselves, whatever they are compared with. */
export const ROLE_COLUMN =
  /^(?:role|roles|user_?role|user_?roles|rol|rolle|access_?level|is_?admin|admin|is_?super_?admin|is_?superuser|superuser|is_?staff|permissions?)$/i;

/** The paren group around token i (its open and close indexes), or the whole statement. */
function enclosing(tk: readonly Token[], i: number): [number, number] {
  let depth = 0;
  for (let j = i - 1; j >= 0; j -= 1) {
    if (isPunct(tk[j], ")")) depth += 1;
    else if (isPunct(tk[j], "(")) {
      if (depth === 0) return [j, groupEnd(tk, j)];
      depth -= 1;
    }
  }
  return [-1, tk.length];
}

/** First `word` at the group depth of `from`, before `end`. */
function findWord(tk: readonly Token[], from: number, end: number, word: string): number {
  let depth = 0;
  for (let j = from; j < end; j += 1) {
    if (isPunct(tk[j], "(")) depth += 1;
    else if (isPunct(tk[j], ")")) depth -= 1;
    else if (depth === 0 && isWord(tk[j], word)) return j;
  }
  return -1;
}

const NOT_ALIAS = new Set(["where", "join", "left", "inner", "on", "limit", "group", "order"]);

function aliasAfter(tk: readonly Token[], at: number): string | null {
  let j = at;
  if (isWord(tk[j], "as")) j += 1;
  const t = tk[j];
  if (t?.kind === "word" && !NOT_ALIAS.has(t.value)) return t.value;
  if (t?.kind === "ident") return t.value.toLowerCase();
  return null;
}

/** The query's WHERE (at its own depth or deeper) reads the caller's identity. */
function readsIdentity(tk: readonly Token[], from: number, end: number): boolean {
  for (let j = from; j < end - 2; j += 1) {
    if (
      isWord(tk[j], "auth") &&
      isPunct(tk[j + 1], ".") &&
      (isWord(tk[j + 2], "uid") || isWord(tk[j + 2], "jwt") || isWord(tk[j + 2], "email"))
    )
      return true;
  }
  return false;
}

/** `auth.uid() in (select id from ... where role = 'admin')`: the caller's id is tested against the query's rows. */
function identityBefore(tk: readonly Token[], start: number): boolean {
  if (start < 1) return false;
  const before = tk
    .slice(Math.max(0, start - 10), start)
    .map((t) => t.raw)
    .join(" ");
  return /auth\s*\.\s*uid\s*\(\s*\)\s*\)?\s*(?:\bin|=\s*any)\s*$/i.test(before);
}

/** A column reference at k: `role`, `p.role`, `profiles.role`, `"role"`; unwraps coalesce(...). */
function columnAt(
  tk: readonly Token[],
  k: number,
  alias: string | null,
  table: string,
): { name: string; next: number } | null {
  let j = k;
  if (isWord(tk[j], "coalesce") && isPunct(tk[j + 1], "(")) j += 2;
  const first = tk[j];
  if (first?.kind !== "word" && first?.kind !== "ident") return null;
  const firstName = first.kind === "word" ? first.value : first.value.toLowerCase();
  if (isPunct(tk[j + 1], "(")) return null;
  let name = firstName;
  let next = j + 1;
  if (isPunct(tk[j + 1], ".")) {
    const second = tk[j + 2];
    if (second?.kind !== "word" && second?.kind !== "ident") return null;
    const bare = table.split(".").pop();
    if (firstName !== alias && firstName !== bare) return null;
    name = second.kind === "word" ? second.value : second.value.toLowerCase();
    next = j + 3;
  } else if (isPunct(tk[j - 1], ".")) {
    return null;
  }
  if (KEYWORDS.has(name)) return null;
  // coalesce(role, 'user'): skip to the closing paren.
  if (next !== k + 1 && isWord(tk[k], "coalesce")) next = groupEnd(tk, k + 1) + 1;
  // role::text
  while (
    isPunct(tk[next], "::") &&
    (tk[next + 1]?.kind === "word" || tk[next + 1]?.kind === "ident")
  )
    next += 2;
  return { name, next };
}

const KEYWORDS = new Set([
  "select",
  "from",
  "where",
  "and",
  "or",
  "not",
  "null",
  "true",
  "false",
  "exists",
  "in",
  "any",
  "all",
  "array",
  "is",
  "as",
  "case",
  "when",
  "then",
  "else",
  "end",
  "limit",
  "auth",
]);

/** `= 'admin'`, `in ('admin', 'owner')`, `= any (array['admin'])`, `@> array['admin']`, `@> '{admin}'`. */
function comparesWithRoleLiteral(tk: readonly Token[], at: number): boolean {
  const op = tk[at];
  if (isWord(op, "in") && isPunct(tk[at + 1], "(")) return literalsIn(tk, at + 1);
  if (op?.kind !== "op" || !(op.raw === "=" || op.raw === "@>")) return false;
  const v = tk[at + 1];
  if (v?.kind === "string") return isRoleValue(v.value);
  if ((isWord(v, "any") || isWord(v, "all")) && isPunct(tk[at + 2], "("))
    return literalsIn(tk, at + 2);
  if (isWord(v, "array") && isPunct(tk[at + 2], "[")) return literalsIn(tk, at + 2);
  return false;
}

/** `'admin' = any (<column or query>)`: the literal sits before `= any (`, which opens at k - 1. */
function literalAnyOf(tk: readonly Token[], k: number): boolean {
  const open = isPunct(tk[k - 1], "(") ? k - 1 : isPunct(tk[k], "(") ? k : -1;
  if (open < 1) return false;
  const any = tk[open - 1];
  const eq = tk[open - 2];
  const lit = tk[open - 3];
  return (
    (isWord(any, "any") || isWord(any, "all")) &&
    eq?.kind === "op" &&
    eq.raw === "=" &&
    lit?.kind === "string" &&
    isRoleValue(lit.value)
  );
}

/** A list of literals only (`('admin', 'owner')`, `array['admin']`) holding a role value; a subquery is not one. */
function literalsIn(tk: readonly Token[], open: number): boolean {
  const close = groupEnd(tk, open);
  let found = false;
  for (let j = open + 1; j < close; j += 1) {
    const t = tk[j];
    if (t?.kind === "string") found ||= isRoleValue(t.value);
    else if (
      !isPunct(t, ",") &&
      !isPunct(t, "[") &&
      !isPunct(t, "]") &&
      !isWord(t, "array") &&
      !isPunct(t, "::") &&
      t?.kind !== "word"
    )
      return false;
    else if (isWord(t, "select")) return false;
  }
  return found;
}

/** `admin`, or a Postgres array literal `{admin,editor}`. */
export function isRoleValue(v: string): boolean {
  return v
    .replace(/^\{|\}$/g, "")
    .split(",")
    .some((x) => ROLE_LITERAL.test(x.trim().replace(/^"|"$/g, "")));
}
