import type { RlsTable } from "./model.js";
import { identOf, qualifiedKey, readQualifiedName } from "./sql-columns.js";
import { groupEnd, isPunct, isWord, type SqlStatement, type Token } from "./sql-lexer.js";

/**
 * Table privileges of `authenticated` from migration GRANT and REVOKE statements, kept only for what
 * a signed-in user may UPDATE or INSERT column by column (`RlsTable.authenticatedWrites`).
 *
 * Supabase grants every privilege on new tables in public to anon and authenticated, so a table
 * starts with every column writable and no entry. The documented way to lock one column is to revoke
 * the table privilege and grant the others back: `revoke update on profiles from authenticated;
 * grant update (full_name, avatar_url) on profiles to authenticated`. A column REVOKE alone
 * (`revoke update (role) ...`) changes nothing while the table privilege stands, as in Postgres.
 * Only `authenticated` counts for a REVOKE (it holds a direct grant, so revoking PUBLIC leaves it);
 * `authenticated` or PUBLIC count for a GRANT. Whole-table SELECT of anon and authenticated is kept
 * too (`RlsTable.selectRevoked`), for views an API role can no longer reach. Never throws.
 */
export function applyTableGrant(tables: Map<string, RlsTable>, stmt: SqlStatement): void {
  const tk = stmt.tokens;
  const grant = isWord(tk[0], "grant");
  if (!grant && !isWord(tk[0], "revoke")) return;
  let i = 1;
  // REVOKE GRANT OPTION FOR only removes the right to re-grant.
  if (!grant && isWord(tk[1], "grant") && isWord(tk[2], "option")) return;
  const on = findTopLevelWord(tk, i, "on");
  if (on < 0) return;
  const privileges = readPrivileges(tk.slice(i, on));
  const select = readsSelect(tk.slice(i, on));
  if (privileges.length === 0 && !select) return;
  i = on + 1;
  let keys: string[] = [];
  if (isWord(tk[i], "all") && isWord(tk[i + 1], "tables") && isWord(tk[i + 2], "in")) {
    const schemas = readIdentList(tk, i + 4);
    keys = [...tables.keys()].filter((k) =>
      schemas.includes(k.includes(".") ? (k.split(".")[0] ?? "") : "public"),
    );
  } else {
    if (isWord(tk[i], "table")) i += 1;
    // FUNCTION, SEQUENCE, SCHEMA and the rest are someone else's business.
    if (tk[i]?.kind === "word" && NOT_A_TABLE.has(tk[i]?.value ?? "")) return;
    for (;;) {
      const q = readQualifiedName(tk, i);
      if (q === null) break;
      keys.push(qualifiedKey(q));
      i = q.next;
      if (!isPunct(tk[i], ",")) break;
      i += 1;
    }
  }
  const roleAt = findTopLevelWord(tk, on, grant ? "to" : "from");
  if (roleAt < 0) return;
  const roles = readIdentList(tk, roleAt + 1);
  if (select) {
    for (const key of keys) {
      const t = tables.get(key);
      if (t) applySelect(t, grant, roles);
    }
  }
  const counts = grant
    ? roles.includes("authenticated") || roles.includes("public")
    : roles.includes("authenticated");
  if (!counts) return;
  for (const key of keys) {
    const t = tables.get(key);
    if (t) for (const p of privileges) applyPrivilege(t, grant, p);
  }
}

/**
 * SELECT for the Data API roles (`RlsTable.selectRevoked`). A REVOKE counts per role named: anon and
 * authenticated hold direct grants in Supabase, so revoking PUBLIC takes nothing from them. A GRANT
 * to PUBLIC gives it back to both.
 */
function applySelect(t: RlsTable, grant: boolean, roles: readonly string[]): void {
  const now = new Set(t.selectRevoked ?? []);
  for (const role of ["anon", "authenticated"] as const) {
    if (grant && (roles.includes(role) || roles.includes("public"))) now.delete(role);
    if (!grant && roles.includes(role)) now.add(role);
  }
  if (now.size === 0) delete t.selectRevoked;
  else t.selectRevoked = [...now].sort();
}

/** `select`, `all [privileges]`; a column list (`select (a, b)`) is not the whole table. */
function readsSelect(tokens: readonly Token[]): boolean {
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (t?.kind !== "word" || (t.value !== "select" && t.value !== "all")) continue;
    if (!isPunct(tokens[i + 1], "(")) return true;
    i = groupEnd(tokens, i + 1);
  }
  return false;
}

const NOT_A_TABLE = new Set([
  "function",
  "functions",
  "procedure",
  "routine",
  "sequence",
  "sequences",
  "schema",
  "database",
  "type",
  "domain",
  "language",
  "tablespace",
  "foreign",
  "large",
]);

interface Privilege {
  kind: "update" | "insert";
  /** Lowercase column names, or null for the whole table. */
  columns: string[] | null;
}

function applyPrivilege(t: RlsTable, grant: boolean, p: Privilege): void {
  const writes = { ...(t.authenticatedWrites ?? {}) };
  const current = writes[p.kind];
  if (grant) {
    if (p.columns === null) delete writes[p.kind];
    else if (current !== undefined) writes[p.kind] = [...new Set([...current, ...p.columns])];
  } else if (p.columns === null) {
    writes[p.kind] = [];
  } else if (current !== undefined) {
    writes[p.kind] = current.filter((c) => !p.columns?.includes(c));
  }
  if (writes.update === undefined && writes.insert === undefined) delete t.authenticatedWrites;
  else t.authenticatedWrites = writes;
}

/** `all [privileges]`, `update (a, b)`, `select, insert`: only UPDATE and INSERT are kept. */
function readPrivileges(tokens: readonly Token[]): Privilege[] {
  const out: Privilege[] = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (t?.kind !== "word") continue;
    const cols = isPunct(tokens[i + 1], "(") ? readColumns(tokens, i + 1) : null;
    if (t.value === "all") {
      out.push({ kind: "update", columns: cols }, { kind: "insert", columns: cols });
    } else if (t.value === "update" || t.value === "insert") {
      out.push({ kind: t.value, columns: cols });
    }
    if (cols !== null) i = groupEnd(tokens, i + 1);
  }
  return out;
}

function readColumns(tokens: readonly Token[], open: number): string[] {
  const close = groupEnd(tokens, open);
  const out: string[] = [];
  for (let i = open + 1; i < close; i += 1) {
    const name = identOf(tokens[i]);
    if (name !== null) out.push(name.toLowerCase());
  }
  return out;
}

function readIdentList(tokens: readonly Token[], from: number): string[] {
  const out: string[] = [];
  for (let i = from; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (isPunct(t, ",")) continue;
    if (isWord(t, "group")) continue;
    const name = identOf(t);
    if (name === null) break;
    const lower = name.toLowerCase();
    if (lower === "with" || lower === "granted" || lower === "cascade" || lower === "restrict")
      break;
    out.push(lower);
  }
  return out;
}

function findTopLevelWord(tokens: readonly Token[], from: number, word: string): number {
  let depth = 0;
  for (let i = from; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (isPunct(t, "(")) depth += 1;
    else if (isPunct(t, ")")) depth = Math.max(0, depth - 1);
    else if (depth === 0 && isWord(t, word)) return i;
  }
  return -1;
}
