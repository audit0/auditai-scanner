import type { RlsTable } from "./model.js";

/**
 * Policies of a table that read the same table directly, where Postgres answers any read by a
 * signed-in user with `infinite recursion detected in policy` (42P17):
 *
 *   create policy "admins read all" on profiles for select
 *     using (exists (select 1 from profiles where id = auth.uid() and role = 'admin'));
 *
 * Every subquery on a table goes through that table's SELECT policies, so a SELECT (or ALL) policy
 * that selects from its own table recurses. A policy for another command only recurses through the
 * SELECT policies it reads, and a helper function (usually SECURITY DEFINER) breaks the loop, which
 * is the usual fix. Only permissive policies that apply to signed-in users count; nothing is concluded
 * when a statement the parser does not evaluate may have changed the table's policies.
 *
 * Supabase refuses UPDATE and DELETE without a filter (pg-safeupdate), and a filtered write reads the
 * rows through the SELECT policies, so on such a table writes by signed-in users fail as well. A
 * running application therefore means the live policies differ from the migrations.
 */
export function recursivePolicies(t: RlsTable): string[] {
  if (t.policiesUnread) return [];
  const bare = t.table.split(".").pop() ?? t.table;
  const schema = t.table.includes(".") ? t.table.split(".")[0] : "public";
  const self = new RegExp(
    `(?<![A-Za-z0-9_$])(?:from|join)\\s+(?:"?${escapeRegex(schema ?? "public")}"?\\s*\\.\\s*)?"?${escapeRegex(bare)}"?(?![A-Za-z0-9_$."])`,
    "i",
  );
  return t.policyDetails
    .filter(
      (p) =>
        p.permissive !== false &&
        (p.command === "select" || p.command === "all") &&
        (p.roles.length === 0 || p.roles.some((r) => r === "authenticated" || r === "public")) &&
        [p.using, p.check].some((e) => e !== null && self.test(e)),
    )
    .map((p) => p.name);
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
