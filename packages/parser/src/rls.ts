import type { PolicyCommand, RlsTable } from "./model.js";
import { qualifiedKey } from "./sql-columns.js";
import { expandDoBlock } from "./sql-do-loops.js";
import { isWord, type SqlStatement, splitSqlStatements } from "./sql-lexer.js";
import {
  applySchemaStatement,
  ensureTable,
  finishSchema,
  type SqlSchemaExtras,
  type SqlSchemaState,
  schemaStateFor,
} from "./sql-schema.js";

/** Returns the text inside the balanced parentheses starting at `open` (index of "("), or null. */
function balanced(text: string, open: number): { inner: string; end: number } | null {
  if (text[open] !== "(") return null;
  let depth = 0;
  for (let i = open; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === "(") depth += 1;
    else if (ch === ")") {
      depth -= 1;
      if (depth === 0) return { inner: text.slice(open + 1, i), end: i };
    }
  }
  return null;
}

// Table after ON: `t`, `"t"`, `public.t`, `"public"."t"` (Drizzle, Makerkit) and other schemas (`storage.objects`).
const QUALIFIED = String.raw`(?:"?([A-Za-z_][A-Za-z0-9_$]*)"?\s*\.\s*)?"?([A-Za-z_][A-Za-z0-9_$]*)"?`;
const CREATE_POLICY = new RegExp(
  String.raw`^create\s+policy\s+("([^"]+)"|\S+)\s+on\s+${QUALIFIED}`,
  "i",
);
// `drop policy if exists "Public insert" on suggestions`: a later migration that takes a policy
// away. Without this the model keeps a policy the database no longer has, and rules judge the
// schema as it was mid-history instead of as it is (wacrm, pasal).
const DROP_POLICY = new RegExp(
  String.raw`^drop\s+policy\s+(?:if\s+exists\s+)?("([^"]+)"|\S+)\s+on\s+${QUALIFIED}`,
  "i",
);

/**
 * False for SQL files the migration tool never applies. The Supabase CLI reads only files directly
 * inside `supabase/migrations/`; archives such as `supabase/migrations/old_migrations/*.sql` sort
 * after the real migrations and would otherwise override them (open-scouts: stale
 * `DISABLE ROW LEVEL SECURITY` statements).
 */
export function isAppliedSqlFile(rel: string): boolean {
  return !/(?:^|\/)supabase\/migrations\/[^/]+\/.+\.sql$/i.test(rel.split("\\").join("/"));
}

/** Folder names that keep SQL for reference (documentation, archives, backups), not the schema itself. */
const REFERENCE_SQL_DIRS: ReadonlySet<string> = new Set([
  "doc",
  "docs",
  "documentation",
  "legacy",
  "archive",
  "archives",
  "archived",
  "backup",
  "backups",
  "deprecated",
  "example",
  "examples",
  "old",
]);

/** A migration the Supabase CLI applies: `<version>_<name>.sql` directly inside `supabase/migrations/`. */
const CLI_MIGRATION = /(?:^|\/)supabase\/migrations\/[0-9]+_[^/]*\.sql$/;
/** The seed the Supabase CLI runs after the migrations. */
const CLI_SEED = /(?:^|\/)supabase\/seed\.sql$/;

/**
 * The SQL files to read as the schema, in application order. Files the migration tool never applies are
 * dropped (see `isAppliedSqlFile`). When the project has Supabase migrations, SQL kept in a folder for
 * documentation, archives or backups (`docs/legacy/COMPLETE_SETUP.sql`, `scripts/archive/...`) is
 * dropped too: the database got its schema from the migrations, and an old setup script's `using
 * (true)` policy would make the model more open than the database (GoalSquad). Without migrations such
 * a file may be the only schema there is, so it stays; so does SQL elsewhere, such as `scripts/` or a
 * root schema dump, which may have been run by hand.
 *
 * SQL the CLI does not apply by itself is read before the CLI migrations, not interleaved by path: a
 * production schema dump (`audit-evidence/.../production-schema-snapshot.sql`), a rollback
 * (`supabase/rollbacks/`) or a hand-run script inside the migrations folder whose name has no version
 * (`DEMO_RESET_SCRIPT_V2.sql`, which sorts after every timestamp) would otherwise override migrations
 * that came later: Costpro's `GRANT ALL ON ALL FUNCTIONS ... TO authenticated` undid 13 later REVOKEs.
 * The seed runs after the migrations, as the CLI runs it.
 */
export function appliedSqlFiles(rels: readonly string[]): string[] {
  const applied = rels.filter(isAppliedSqlFile);
  const slashed = (rel: string): string => rel.split("\\").join("/");
  const hasMigrations = applied.some((rel) =>
    /(?:^|\/)supabase\/migrations\/[^/]+\.sql$/i.test(slashed(rel)),
  );
  if (!hasMigrations) return applied;
  const kept = applied.filter(
    (rel) =>
      !slashed(rel)
        .split("/")
        .slice(0, -1)
        .some((dir) => REFERENCE_SQL_DIRS.has(dir.toLowerCase())),
  );
  const migrations = kept.filter((rel) => CLI_MIGRATION.test(slashed(rel)));
  if (migrations.length === 0) return kept;
  const seeds = kept.filter((rel) => CLI_SEED.test(slashed(rel)));
  const byHand = kept.filter(
    (rel) => !CLI_MIGRATION.test(slashed(rel)) && !CLI_SEED.test(slashed(rel)),
  );
  return [...byHand, ...migrations, ...seeds];
}

/**
 * Extracts table columns, RLS state, policy details, enums, functions and storage buckets from
 * migration SQL. Call once per file in application order: later statements override earlier ones.
 * Schema-level results that do not fit RlsTable are read back with `sqlSchemaFor(into)`.
 * Never throws on malformed SQL.
 */
export function parseSqlForRls(rel: string, text: string, into: Map<string, RlsTable>): void {
  if (!isAppliedSqlFile(rel)) return;
  const state = schemaStateFor(into);
  for (const stmt of splitSqlStatements(text)) {
    applyStatement(state, stmt, rel);
    if (!isWord(stmt.tokens[0], "do")) continue;
    // `foreach t in array array['a', 'b'] loop execute format('alter table %I ...', t)`: the loop
    // is unrolled and each expanded statement applied like a top-level one.
    const expanded = expandDoBlock(stmt);
    for (const s of expanded.statements) applyStatement(state, s, rel);
    if (expanded.dynamic) warnDynamicSql(state, rel);
  }
}

/** One warning per file: the block runs SQL the scanner cannot evaluate statically. */
function warnDynamicSql(state: SqlSchemaState, rel: string): void {
  const w = `${rel}: a DO block runs dynamic SQL (a loop over a query, or an EXECUTE that is conditional or built from expressions); RLS, policies and privileges it sets are not seen`;
  if (!state.warnings.includes(w)) state.warnings.push(w);
}

const ROLE_NAME = '(?:"[A-Za-z_][A-Za-z0-9_]*"|[A-Za-z_][A-Za-z0-9_]*)';
const ROLES = new RegExp(`\\bto\\s+(${ROLE_NAME}(?:\\s*,\\s*${ROLE_NAME})*)`, "i");

/** Where the policy header ends: the first USING or WITH CHECK, or the whole rest. */
function headEnd(rest: string): number {
  const u = /\busing\s*\(/i.exec(rest);
  const c = /\bwith\s+check\s*\(/i.exec(rest);
  const ends = [u?.index, c?.index].filter((i): i is number => i !== undefined);
  return ends.length === 0 ? rest.length : Math.min(...ends);
}

/** CREATE POLICY goes to the table's policy list; everything else to the schema handlers. */
function applyStatement(state: SqlSchemaState, stmt: SqlStatement, rel: string): void {
  const cp = CREATE_POLICY.exec(stmt.text);
  if (!cp?.[1] || !cp[4]) {
    dropPolicy(state, stmt) || applySchemaStatement(state, stmt, rel);
    return;
  }
  const t = ensureTable(
    state,
    qualifiedKey({ schema: cp[3] ?? null, name: cp[4] }),
    rel,
    stmt.line,
  );
  const name = cp[2] ?? cp[1];
  const rest = stmt.text.slice(cp[0].length);
  const cmdMatch = /\bfor\s+(select|insert|update|delete|all)\b/i.exec(rest);
  const command = (cmdMatch?.[1]?.toLowerCase() as PolicyCommand | undefined) ?? "all";
  // The TO clause only exists before USING / WITH CHECK; looking further would pick up a column
  // named `to` inside a predicate. Role names may be quoted (`TO "authenticated"`, what
  // `supabase db dump` writes), and an empty list means PUBLIC, which includes anon.
  const head = rest.slice(0, headEnd(rest));
  const rolesMatch = ROLES.exec(head);
  const roles = rolesMatch?.[1]
    ? rolesMatch[1].split(/\s*,\s*/).map((r) => r.replace(/"/g, "").toLowerCase())
    : [];
  let using: string | null = null;
  let check: string | null = null;
  const u = /\busing\s*\(/i.exec(rest);
  if (u) using = balanced(rest, u.index + u[0].length - 1)?.inner.trim() ?? null;
  const c = /\bwith\s+check\s*\(/i.exec(rest);
  if (c) check = balanced(rest, c.index + c[0].length - 1)?.inner.trim() ?? null;
  t.policies.push(name);
  t.policyDetails.push({
    name,
    command,
    roles,
    using,
    check,
    location: { file: rel, line: stmt.line },
  });
}

/**
 * `DROP POLICY [IF EXISTS] name ON table`: removes the policy from a table the model already knows.
 * Returns true when the statement was a DROP POLICY, so the caller stops. A drop on an unknown
 * table is still consumed; it creates nothing.
 */
function dropPolicy(state: SqlSchemaState, stmt: SqlStatement): boolean {
  const dp = DROP_POLICY.exec(stmt.text);
  if (!dp?.[1] || !dp[4]) return false;
  const name = dp[2] ?? dp[1].replace(/^"|"$/g, "");
  const t = state.tables.get(qualifiedKey({ schema: dp[3] ?? null, name: dp[4] }));
  if (t) {
    t.policies = t.policies.filter((p) => p !== name);
    t.policyDetails = t.policyDetails.filter((p) => p.name !== name);
  }
  return true;
}

/** Enums, SQL functions and storage buckets accumulated by `parseSqlForRls` calls on `into`. */
export function sqlSchemaFor(into: Map<string, RlsTable>): SqlSchemaExtras {
  return finishSchema(schemaStateFor(into));
}
