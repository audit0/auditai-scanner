import type { PolicyCommand, RlsTable } from "./model.js";
import { qualifiedKey } from "./sql-columns.js";
import { splitSqlStatements } from "./sql-lexer.js";
import {
  applySchemaStatement,
  ensureTable,
  finishSchema,
  type SqlSchemaExtras,
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

/**
 * False for SQL files the migration tool never applies. The Supabase CLI reads only files directly
 * inside `supabase/migrations/`; archives such as `supabase/migrations/old_migrations/*.sql` sort
 * after the real migrations and would otherwise override them (open-scouts: stale
 * `DISABLE ROW LEVEL SECURITY` statements).
 */
export function isAppliedSqlFile(rel: string): boolean {
  return !/(?:^|\/)supabase\/migrations\/[^/]+\/.+\.sql$/i.test(rel.split("\\").join("/"));
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
    const cp = CREATE_POLICY.exec(stmt.text);
    if (!cp?.[1] || !cp[4]) {
      applySchemaStatement(state, stmt, rel);
      continue;
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
    const rolesMatch = /\bto\s+([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*)/i.exec(
      rest,
    );
    const roles = rolesMatch?.[1] ? rolesMatch[1].split(/\s*,\s*/).map((r) => r.toLowerCase()) : [];
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
}

/** Enums, SQL functions and storage buckets accumulated by `parseSqlForRls` calls on `into`. */
export function sqlSchemaFor(into: Map<string, RlsTable>): SqlSchemaExtras {
  return finishSchema(schemaStateFor(into));
}
