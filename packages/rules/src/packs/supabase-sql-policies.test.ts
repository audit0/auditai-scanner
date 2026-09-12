import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Finding } from "@auditai/core";
import { buildGraph } from "@auditai/graph";
import { parseProject } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { runRules } from "../rule.js";
import { supabaseSqlPoliciesPack } from "./supabase-sql-policies.js";

/**
 * The three migration-only rules. They need no application code, so every case here is SQL; the
 * shapes come from the knowledge base (`knowledge/patterns/next-supabase`) and from the 26-repository
 * corpus of 13 September 2026.
 */

function scan(sql: string, files: Record<string, string> = {}): Finding[] {
  const dir = mkdtempSync(join(tmpdir(), "auditai-sql-policies-"));
  const all = { "supabase/migrations/0001.sql": sql, ...files };
  for (const [rel, text] of Object.entries(all)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  const model = parseProject(dir, { sqlDirs: ["supabase/migrations"] });
  return runRules(supabaseSqlPoliciesPack, model, buildGraph(model), {
    now: "2026-09-12T00:00:00Z",
  });
}

const ids = (fs: Finding[]): string[] => fs.map((f) => f.ruleId.replace("supabase.", "")).sort();

const NOTES = `create table public.notes (id uuid primary key, owner_id uuid not null, body text);
alter table public.notes enable row level security;
`;

describe("rls-policy-trusts-user-metadata", () => {
  it("fires on a claim read out of the JWT and names the policy", () => {
    const f = scan(
      `${NOTES}create policy "admin reads all" on public.notes for select to authenticated
         using ((((select auth.jwt()) -> 'user_metadata' ->> 'is_admin'))::boolean);`,
    );
    expect(ids(f)).toEqual(["rls-policy-trusts-user-metadata"]);
    expect(f[0]?.severity).toBe("critical");
    expect(f[0]?.title).toContain("admin reads all");
    expect(f[0]?.evidence[0]?.summary).toContain("user_metadata");
    // Critical findings with deterministic evidence block a pull request; this one waits for
    // real-world measurement first.
    expect(f[0]?.evidence[0]?.data?.deterministic).toBeUndefined();
  });

  it("fires on raw_user_meta_data read from auth.users", () => {
    const f = scan(
      `${NOTES}create policy "admin reads all" on public.notes for select to authenticated
         using ((select raw_user_meta_data ->> 'role' from auth.users where id = auth.uid()) = 'admin');`,
    );
    expect(ids(f)).toEqual(["rls-policy-trusts-user-metadata"]);
  });

  it("stays silent on app_metadata and on a table column that happens to be called user_metadata", () => {
    const f = scan(
      `create table public.profiles (id uuid primary key, user_metadata jsonb, raw_user_meta_data jsonb);
alter table public.profiles enable row level security;
create policy "app_metadata admin" on public.profiles for select to authenticated
  using ((((select auth.jwt()) -> 'app_metadata' ->> 'is_admin'))::boolean);
create policy "own row" on public.profiles for update to authenticated
  using (id = auth.uid()) with check (user_metadata is not null and raw_user_meta_data is not null);`,
    );
    expect(ids(f)).toEqual([]);
  });
});

describe("policies-without-rls-enabled", () => {
  it("fires when policies exist and row level security was never enabled", () => {
    const f = scan(
      `create table public.pages (id uuid primary key, workspace_id uuid not null);
create policy "members read" on public.pages for select to authenticated using (workspace_id = auth.uid());
create policy "members write" on public.pages for insert to authenticated with check (workspace_id = auth.uid());`,
    );
    expect(ids(f)).toEqual(["policies-without-rls-enabled"]);
    expect(f[0]?.severity).toBe("high");
    expect(f[0]?.evidence[0]?.summary).toContain("members read");
  });

  it("stays silent once RLS is enabled, and on a table with no policies at all", () => {
    const f = scan(
      `create table public.pages (id uuid primary key, workspace_id uuid not null);
alter table public.pages enable row level security;
create policy "members read" on public.pages for select to authenticated using (workspace_id = auth.uid());
create table public.logs (id uuid primary key, line text);`,
    );
    expect(ids(f)).toEqual([]);
  });

  it("stays silent when a later migration enables RLS", () => {
    const f = scan(
      `create table public.pages (id uuid primary key);
create policy "read" on public.pages for select to authenticated using (true);`,
      { "supabase/migrations/0002.sql": "alter table public.pages enable row level security;" },
    );
    expect(ids(f).filter((r) => r === "policies-without-rls-enabled")).toEqual([]);
  });
});

describe("anon-write-policy", () => {
  it("reports an open delete policy as high", () => {
    const f = scan(
      `${NOTES}create policy "anyone deletes" on public.notes for delete to anon, authenticated using (true);`,
    );
    expect(ids(f)).toEqual(["anon-write-policy"]);
    expect(f[0]?.severity).toBe("high");
    expect(f[0]?.sinks).toEqual(["supabase.delete:public.notes"]);
  });

  it("reports an insert-only policy as medium and says to confirm the intent", () => {
    const f = scan(
      `${NOTES}create policy "anyone subscribes" on public.notes for insert to anon with check (true);`,
    );
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("medium");
    expect(f[0]?.evidence[0]?.summary).toContain("meant to accept rows from strangers");
  });

  it("treats a missing TO clause as PUBLIC", () => {
    const f = scan(`${NOTES}create policy "open update" on public.notes for update using (true);`);
    expect(ids(f)).toEqual(["anon-write-policy"]);
    expect(f[0]?.severity).toBe("high");
  });

  it("stays silent for authenticated-only policies, scoped predicates and select policies", () => {
    const f = scan(
      `${NOTES}create policy "members delete" on public.notes for delete to authenticated using (owner_id = auth.uid());
create policy "anon reads" on public.notes for select to anon using (true);
create policy "service writes" on public.notes for all to service_role using (true) with check (true);
create policy "quoted role" on public.notes for update to "authenticated" using (true);`,
    );
    expect(ids(f)).toEqual([]);
  });

  it("stays silent once a later migration drops the open policy", () => {
    const f = scan(
      `${NOTES}create policy "anyone deletes" on public.notes for delete to anon using (true);`,
      {
        "supabase/migrations/0002.sql": `drop policy if exists "anyone deletes" on public.notes;`,
      },
    );
    expect(ids(f)).toEqual([]);
  });

  it("leaves a table without RLS to the other rules", () => {
    const f = scan(
      `create table public.notes (id uuid primary key, owner_id uuid);
create policy "anyone deletes" on public.notes for delete to anon using (true);`,
    );
    expect(ids(f)).toEqual(["policies-without-rls-enabled"]);
  });
});
