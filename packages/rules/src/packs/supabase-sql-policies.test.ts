import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Finding } from "@auditai/core";
import { buildGraph } from "@auditai/graph";
import { parseProject, type RlsTable } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { runRules } from "../rule.js";
import { roleGate, supabaseSqlPoliciesPack, writeReach } from "./supabase-sql-policies.js";

/**
 * The three migration-only rules. They need no application code, so every case here is SQL; the
 * shapes come from the knowledge base (`knowledge/patterns/next-supabase`) and from the 26-repository
 * corpus of 13 September 2026.
 */

/** `live`: the model stands for a live database (a snapshot), where a missing policy is a fact. */
function scanFiles(sql: string, files: Record<string, string> = {}, live = false): Finding[] {
  const dir = mkdtempSync(join(tmpdir(), "auditai-sql-policies-"));
  const all = { "supabase/migrations/0001.sql": sql, ...files };
  for (const [rel, text] of Object.entries(all)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  const parsed = parseProject(dir, { sqlDirs: ["supabase/migrations"] });
  const model = live ? { ...parsed, fromLiveDatabase: true as const } : parsed;
  return runRules(supabaseSqlPoliciesPack, model, buildGraph(model), {
    now: "2026-09-12T00:00:00Z",
  });
}

const scan = (sql: string, files: Record<string, string> = {}): Finding[] => scanFiles(sql, files);

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
      `${NOTES}create policy "anyone deletes" on public.notes for delete to anon, authenticated using (true);
create policy "anyone reads" on public.notes for select to anon using (true);`,
    );
    expect(ids(f)).toEqual(["anon-write-policy"]);
    expect(f[0]?.severity).toBe("high");
    expect(f[0]?.tier).toBeUndefined();
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
    const f = scan(`${NOTES}create policy "open update" on public.notes for update using (true);
create policy "open read" on public.notes for select using (true);`);
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

/**
 * An UPDATE or DELETE through the Data API reaches only the rows the same visitor can read: Supabase
 * refuses one without a filter (safeupdate), and a filter that reads a column makes Postgres apply the
 * SELECT policies too. Measured against a real PostgREST and pg_graphql on 24 September 2026
 * (docs/realworld/2026-09-24-write-needs-read.md); each shape below was probed there.
 */
describe("anon-write-policy: a change reaches only the rows the visitor can read", () => {
  // The shapes are read as a live database holds them; what a migration scan may conclude is below.
  const scan = (sql: string, files: Record<string, string> = {}) => scanFiles(sql, files, true);
  const OPEN_UPDATE = `${NOTES}create policy "open update" on public.notes for update using (true);\n`;
  const data = (f: Finding | undefined) => f?.evidence[0]?.data ?? {};

  it("makes an open update a lead when no policy lets anyone read the table", () => {
    const [f, ...rest] = scan(OPEN_UPDATE);
    expect(rest).toEqual([]);
    expect(f?.ruleId).toBe("supabase.anon-write-policy");
    expect(f?.tier).toBe("lead");
    // What the rule said is kept; applyTiers caps the claim (tiers.test.ts).
    expect(f?.severity).toBe("high");
    expect(data(f)).toMatchObject({ reach: "no-row", stranger: "anon", readPolicies: [] });
    expect(f?.title).toBe(
      'Policy "open update" would let anyone update "notes", but no policy lets them read it',
    );
    expect(f?.evidence[0]?.summary).toContain(
      "no policy lets anon or signed-in users read public.notes",
    );
    expect(f?.evidence[0]?.summary).toContain(
      "the moment a SELECT policy for these roles is added",
    );
    expect(f?.evidence[0]?.summary).toContain("safeupdate");
  });

  it("does the same for an open delete", () => {
    const [f] = scan(
      `${NOTES}create policy "open delete" on public.notes for delete to anon using (true);`,
    );
    expect(f?.tier).toBe("lead");
    expect(data(f)).toMatchObject({ reach: "no-row" });
  });

  it("keeps the headline when a SELECT policy lets anyone read every row", () => {
    const [f] = scan(
      `${OPEN_UPDATE}create policy "anyone reads" on public.notes for select to anon using (true);`,
    );
    expect(f?.tier).toBeUndefined();
    expect(data(f)).toMatchObject({
      reach: "every-row",
      stranger: "anon",
      readPolicies: ["anyone reads"],
    });
    expect(f?.title).toBe('Policy "open update" lets anyone update "notes"');
  });

  it("rewords the headline to the rows they can read when a condition decides the read", () => {
    const [f] = scan(
      `${OPEN_UPDATE}create policy "published only" on public.notes for select using (body is not null);`,
    );
    expect(f?.tier).toBeUndefined();
    expect(f?.severity).toBe("high");
    expect(data(f)).toMatchObject({ reach: "readable-rows", readPolicies: ["published only"] });
    expect(f?.title).toBe(
      'Policy "open update" lets anyone update the rows of "notes" they can read',
    );
    expect(f?.evidence[0]?.summary).toContain('"published only" USING body is not null');
  });

  it("counts a FOR ALL policy as a read, and a FOR ALL write policy reads every row itself", () => {
    const [viaAll] = scan(
      `${OPEN_UPDATE}create policy "anon sees drafts" on public.notes for all to anon using (body = 'draft') with check (false);`,
    );
    expect(data(viaAll)).toMatchObject({
      reach: "readable-rows",
      readPolicies: ["anon sees drafts"],
    });
    const [all] = scan(
      `${NOTES}create policy "open" on public.notes for all using (true) with check (true);`,
    );
    expect(all?.tier).toBeUndefined();
    expect(data(all)).toMatchObject({ reach: "every-row", readPolicies: ["open"] });
  });

  it("weighs RESTRICTIVE policies: a condition narrows the read, false refuses every row", () => {
    const narrowed = scan(
      `${OPEN_UPDATE}create policy "anyone reads" on public.notes for select using (true);
create policy "only public ones" on public.notes as restrictive for select using (body = 'public');`,
    );
    expect(data(narrowed[0])).toMatchObject({
      reach: "readable-rows",
      readPolicies: ["anyone reads", "only public ones"],
    });
    const refused = scan(
      `${OPEN_UPDATE}create policy "anyone reads" on public.notes for select using (true);
create policy "no browser access" on public.notes as restrictive for all to anon, authenticated using (false) with check (false);`,
    );
    expect(refused[0]?.tier).toBe("lead");
    expect(data(refused[0])).toMatchObject({ reach: "no-row", refusedBy: "no browser access" });
    expect(refused[0]?.evidence[0]?.summary).toContain('RESTRICTIVE policy "no browser access"');
    // A RESTRICTIVE policy alone opens nothing: `using (true)` on it lets nobody read.
    const alone = scan(
      `${OPEN_UPDATE}create policy "restrictive only" on public.notes as restrictive for select using (true);`,
    );
    expect(data(alone[0])).toMatchObject({ reach: "no-row" });
    // One that refuses the write itself.
    const noUpdates = scan(
      `${OPEN_UPDATE}create policy "anyone reads" on public.notes for select using (true);
create policy "frozen" on public.notes as restrictive for update using (false);`,
    );
    expect(data(noUpdates[0])).toMatchObject({ reach: "no-row", refusedBy: "frozen" });
  });

  it("names signed-in users when only they can read what a PUBLIC policy lets anyone change", () => {
    const [f] = scan(
      `${OPEN_UPDATE}create policy "members read" on public.notes for select to authenticated using (true);`,
    );
    expect(f?.tier).toBeUndefined();
    expect(data(f)).toMatchObject({ reach: "every-row", stranger: "authenticated" });
    expect(f?.title).toBe('Policy "open update" lets anyone who signs up update "notes"');
    // A policy for anon alone does not reach signed-in users, whatever they may read.
    const [anonOnly] = scan(
      `${NOTES}create policy "anon updates" on public.notes for update to anon using (true);
create policy "members read" on public.notes for select to authenticated using (true);`,
    );
    expect(anonOnly?.tier).toBe("lead");
  });

  it("reads a role gate per role: signed-in users read what anon cannot, the service role is nobody", () => {
    // aureluzdesign (fifth blind sample): an open update, and a read for PUBLIC gated on the role.
    const [signedIn] = scan(
      `${OPEN_UPDATE}create policy "Admin can read" on public.notes for select using (auth.role() = 'authenticated');`,
    );
    expect(signedIn?.tier).toBeUndefined();
    expect(data(signedIn)).toMatchObject({ reach: "every-row", stranger: "authenticated" });
    expect(signedIn?.title).toBe('Policy "open update" lets anyone who signs up update "notes"');
    const [serviceOnly] = scan(
      `${OPEN_UPDATE}create policy "service reads" on public.notes for select using ((select auth.role()) = 'service_role');`,
    );
    expect(serviceOnly?.tier).toBe("lead");
    const [uid] = scan(
      `${OPEN_UPDATE}create policy "members" on public.notes for select using (auth.uid() is not null);`,
    );
    expect(data(uid)).toMatchObject({ reach: "every-row", stranger: "authenticated" });
    // A RESTRICTIVE gate refuses the roles it does not admit.
    const [gated] = scan(
      `${OPEN_UPDATE}create policy "anyone reads" on public.notes for select using (true);
create policy "members only" on public.notes as restrictive for all using (auth.uid() is not null);`,
    );
    expect(data(gated)).toMatchObject({ reach: "every-row", stranger: "authenticated" });
  });

  it("names a function the visitor can call that changes the table: safeupdate does not stop every such write", () => {
    // Skeptic review, 24 September 2026: `where true`, a BEGIN ATOMIC body and MERGE get past safeupdate,
    // and a write that reads no column is not limited by any SELECT policy.
    const shapes = [
      `create function public.wipe() returns void language plpgsql as $$ begin update public.notes set body = null where true; end $$;`,
      `create function public.wipe() returns void language sql begin atomic delete from public.notes; end;`,
      `create function public.wipe(p text) returns void language plpgsql as $$ begin merge into notes using (select 1) s on true when matched then update set body = p; end $$;`,
      `create function public.wipe(t text) returns void language plpgsql as $$ begin execute format('update %I set body = null where true', t); end $$;`,
      // Skeptic review, round 2: the statement passed in by the caller, and a comment before the name.
      `create function public.wipe(query text) returns void language plpgsql as $$ begin execute query; end $$;`,
      `create function public.wipe() returns void language plpgsql as $$ begin update /* every row */ public.notes set body = null where true; end $$;`,
      `create function public.wipe() returns void language sql as $$ truncate table public.notes $$;`,
      // A trigger runs with the rights of whoever writes its table, EXECUTE grant or not.
      `create function public.wipe() returns trigger language plpgsql as $$ begin update public.notes set body = null where true; return new; end $$;
revoke execute on function public.wipe() from public, anon, authenticated;`,
    ];
    for (const fn of shapes) {
      const [f] = scan(`${OPEN_UPDATE}${fn}`);
      expect(f?.tier, fn).toBe("lead");
      expect(data(f), fn).toMatchObject({ reach: "no-row", writers: ["wipe"] });
      expect(f?.title, fn).toBe(
        'Policy "open update" would let anyone update "notes"; no policy lets them read it, but function wipe() can change it',
      );
      expect(f?.evidence[0]?.summary, fn).toContain("WHERE true, a BEGIN ATOMIC body, MERGE");
    }
    // The rows they can read stay a true lower bound; the function is named next to them.
    const [readable] = scan(
      `${OPEN_UPDATE}create policy "published" on public.notes for select using (body is not null);\n${shapes[0]}`,
    );
    expect(readable?.tier).toBeUndefined();
    expect(data(readable)).toMatchObject({ reach: "readable-rows", writers: ["wipe"] });
  });

  it("does not name a function the visitor cannot run as themselves or cannot call at all", () => {
    const body = `language plpgsql as $$ begin update public.notes set body = null where true; end $$`;
    for (const fn of [
      // SECURITY DEFINER skips RLS entirely: the definer rule's subject, not this policy's.
      `create function public.wipe() returns void ${body} security definer;`,
      `create function public.wipe() returns void ${body};\nrevoke execute on function public.wipe() from public, anon, authenticated;`,
      `create function private.wipe() returns void ${body};`,
    ]) {
      const [f] = scan(`${OPEN_UPDATE}${fn}`);
      expect(data(f).writers, fn).toBeUndefined();
      expect(f?.title, fn).toContain("but no policy lets them read it");
    }
    // A RESTRICTIVE false on the write refuses a function's write too.
    const [refused] = scan(
      `${OPEN_UPDATE}create policy "frozen" on public.notes as restrictive for update using (false);
create function public.wipe() returns void ${body};`,
    );
    expect(data(refused).writers).toBeUndefined();
  });

  it("keeps every row when a migration switches safeupdate off for the API role, however it is written", () => {
    for (const setting of [
      "alter role authenticator set safeupdate.enabled = off;",
      "alter role authenticator in database postgres set safeupdate.enabled to 'false';",
      "alter role authenticator set pgrst.db_pre_request = 'public.before_request';",
      `alter role authenticator set "safeupdate"."enabled" = off;`,
      "set safeupdate.enabled = off;\nalter role authenticator set safeupdate.enabled from current;",
      "do $$ begin if exists (select 1 from pg_roles where rolname = 'authenticator') then alter role authenticator set safeupdate.enabled = off; end if; end $$;",
      "alter role all set safeupdate.enabled = off;",
      "alter database postgres set safeupdate.enabled = 0;",
    ]) {
      const [f] = scan(`${OPEN_UPDATE}${setting}`);
      expect(f?.tier, setting).toBeUndefined();
      expect(data(f), setting).toMatchObject({ reach: "every-row" });
    }
    // Once seen off, it stays off: which value Postgres keeps after resets at other levels is not
    // worked out here (a role+database value survives a role reset, RESET ALL run by the owner keeps it).
    const [back] = scan(
      `${OPEN_UPDATE}alter role authenticator set safeupdate.enabled = off;\nalter role authenticator reset all;`,
    );
    expect(data(back)).toMatchObject({ reach: "every-row" });
    // Switching it on, or a comment about it, changes nothing.
    const [on] = scan(
      `${OPEN_UPDATE}-- safeupdate.enabled = off would break the API\nalter role authenticator set safeupdate.enabled = on;`,
    );
    expect(on?.tier).toBe("lead");
  });

  it("concludes nothing from a missing read policy where the migrations hold policy SQL it does not evaluate", () => {
    // Skeptic review, 24 September 2026: a read policy created in a DO block, a policy widened by
    // ALTER POLICY, a RESTRICTIVE one dropped in a DO block. The finding says what it said before.
    for (const extra of [
      `do $$ begin if not exists (select 1 from pg_policies where policyname = 'Public read') then
         create policy "Public read" on public.notes for select using (true); end if; end $$;`,
      `create policy "read own" on public.notes for select to authenticated using (auth.uid() = owner_id);
alter policy "read own" on public.notes to anon, authenticated using (true);`,
      `create policy "anyone reads" on public.notes for select using (true);
create policy "no browser" on public.notes as restrictive for select to anon using (false);
do $$ begin if exists (select 1 from pg_policies where policyname = 'no browser') then
  drop policy "no browser" on public.notes; end if; end $$;`,
    ]) {
      const [f] = scan(`${OPEN_UPDATE}${extra}`);
      expect(f?.tier, extra).toBeUndefined();
      expect(data(f), extra).toMatchObject({ reach: "every-row", policiesUnread: true });
      expect(f?.evidence[0]?.summary, extra).toContain("not known from the migrations");
    }
    // A DO block the parser does evaluate (an unconditional drop) gives the exact answer.
    const [exact] = scan(
      `${OPEN_UPDATE}create policy "anyone reads" on public.notes for select using (true);
create policy "no browser" on public.notes as restrictive for select to anon using (false);
do $$ begin drop policy if exists "no browser" on public.notes; end $$;`,
    );
    expect(data(exact)).toMatchObject({ reach: "every-row", stranger: "anon" });
    // Dynamic policy SQL anywhere: no table's policy list is complete.
    const [dynamic] = scan(
      `${OPEN_UPDATE}do $$ declare t text; begin for t in select tablename from pg_tables where schemaname = 'public' loop
         execute format('create policy "read" on public.%I for select using (true)', t); end loop; end $$;`,
    );
    expect(data(dynamic)).toMatchObject({ reach: "every-row", policiesUnread: true });
    // A DO block about another table changes nothing here.
    const [other] = scan(
      `${OPEN_UPDATE}do $$ begin create policy "x" on public.elsewhere for select using (true); end $$;`,
    );
    expect(other?.tier).toBe("lead");
  });

  it("counts a read policy for a project role as a possible read: anon may be a member of it", () => {
    const [f] = scan(
      `${OPEN_UPDATE}create policy "visitors read" on public.notes for select to site_visitor using (true);`,
    );
    expect(f?.tier).toBeUndefined();
    expect(data(f)).toMatchObject({ reach: "readable-rows", readPolicies: ["visitors read"] });
    // The service role is not anyone's role.
    const [service] = scan(
      `${OPEN_UPDATE}create policy "service reads" on public.notes for select to service_role using (true);`,
    );
    expect(service?.tier).toBe("lead");
  });

  it("reports a FOR ALL policy that still lets strangers add rows as an open insert, not a lead", () => {
    for (const restrictive of [
      `create policy "Nobody reads logs" on public.notes as restrictive for select to anon using (false);`,
      `create policy "No reads" on public.notes as restrictive for all to anon using (false) with check (true);`,
    ]) {
      const [f] = scan(
        `${NOTES}create policy "Anyone can log" on public.notes for all to anon using (true) with check (true);\n${restrictive}`,
      );
      expect(f?.tier, restrictive).toBeUndefined();
      expect(f?.severity, restrictive).toBe("medium");
      expect(data(f), restrictive).toMatchObject({ reach: "add-rows", stranger: "anon" });
      expect(f?.title, restrictive).toBe('Policy "Anyone can log" lets anyone add rows to "notes"');
    }
    // A RESTRICTIVE one that refuses new rows too leaves nothing: a lead.
    const [none] = scan(
      `${NOTES}create policy "Anyone can log" on public.notes for all to anon using (true) with check (true);
create policy "Nothing" on public.notes as restrictive for all to anon using (false);`,
    );
    expect(none?.tier).toBe("lead");
  });

  it("says what a visitor without an account can change next to what a signed-in one can", () => {
    const [both] = scan(
      `${OPEN_UPDATE}create policy "Public read" on public.notes for select to anon using (body = 'public');
create policy "Members read" on public.notes for select to authenticated using (true);`,
    );
    expect(data(both)).toMatchObject({ reach: "every-row", stranger: "authenticated" });
    expect(both?.evidence[0]?.summary).toContain(
      "A visitor without an account changes the rows they can read",
    );
    expect(both?.evidence[0]?.summary).not.toContain("changes none");
    // Both can read some rows: both conditions are quoted.
    const [some] = scan(
      `${OPEN_UPDATE}create policy "Public read" on public.notes for select to anon using (body = 'public');
create policy "Members read" on public.notes for select to authenticated using (auth.uid() is not null and body is not null);`,
    );
    expect(data(some)).toMatchObject({
      reach: "readable-rows",
      readPolicies: ["Public read", "Members read"],
    });
    expect(some?.evidence[0]?.summary).toContain("what a signed-in user can read is decided by");
  });

  it("keeps the claim on a migration scan, which cannot show that a read policy is absent", () => {
    // The dashboard, a function a later statement calls, SQL the parser does not evaluate: a
    // migration scan misses policies made there (skeptic review, 24 September 2026).
    const [f] = scanFiles(OPEN_UPDATE);
    expect(f?.tier).toBeUndefined();
    expect(f?.severity).toBe("high");
    expect(f?.title).toBe('Policy "open update" lets anyone update "notes"');
    expect(data(f)).toMatchObject({ reach: "no-row", migrationsOnly: true });
    expect(f?.evidence[0]?.summary).toContain("a snapshot of the live database says otherwise");
    // A FOR ALL policy is not lowered to an open insert from migrations either.
    const [all] = scanFiles(
      `${NOTES}create policy "Anyone can log" on public.notes for all to anon using (true) with check (true);
create policy "Nobody reads logs" on public.notes as restrictive for select to anon using (false);`,
    );
    expect(all?.severity).toBe("high");
    expect(data(all)).toMatchObject({ migrationsOnly: true });
    // The wording that narrows by what can be read stays: it is a true lower bound.
    const [readable] = scanFiles(
      `${OPEN_UPDATE}create policy "published" on public.notes for select using (body is not null);`,
    );
    expect(data(readable)).toMatchObject({ reach: "readable-rows" });
    // Without a snapshot, nothing is said about what anon cannot do.
    const [signedUp] = scanFiles(
      `${OPEN_UPDATE}create policy "members read" on public.notes for select to authenticated using (true);`,
    );
    expect(signedUp?.evidence[0]?.summary).not.toContain("changes none");
    expect(signedUp?.evidence[0]?.summary).toContain("a snapshot of the live database settles");
  });

  it("leaves an insert policy as it was: an insert reads no existing row", () => {
    const [f] = scan(
      `${NOTES}create policy "form" on public.notes for insert to anon with check (true);`,
    );
    expect(f?.tier).toBeUndefined();
    expect(f?.severity).toBe("medium");
    expect(data(f).reach).toBeUndefined();
  });
});

describe("roleGate", () => {
  it("reads the role a predicate admits as migrations and pg_policies write it", () => {
    const gate = (e: string) => [...(roleGate(e) ?? ["-"])].join(",");
    expect(gate("auth.role() = 'authenticated'")).toBe("authenticated");
    expect(gate("(auth.role() = 'authenticated'::text)")).toBe("authenticated");
    expect(gate("(( SELECT auth.role() AS role) = 'service_role'::text)")).toBe("service_role");
    expect(gate("'anon' = auth.role()")).toBe("anon");
    expect(gate("((auth.jwt() ->> 'role'::text) = 'authenticated'::text)")).toBe("authenticated");
    expect(gate("(auth.uid() IS NOT NULL)")).toBe("authenticated");
    expect(gate("(( SELECT auth.uid() AS uid) IS NOT NULL)")).toBe("authenticated");
    // Anything that also looks at the row, or at more than the role, is not a gate.
    expect(gate("((auth.role() = 'authenticated'::text) AND (owner_id = auth.uid()))")).toBe("-");
    expect(gate("(auth.role() = 'authenticated') or (auth.role() = 'anon')")).toBe("-");
    // Postgres compares the literal as written: these admit nobody, so they are no gate.
    expect(gate("auth.role() = 'Authenticated'")).toBe("-");
    expect(gate("auth.role() = 'authenticated '")).toBe("-");
    expect(gate("(auth.jwt() ->> 'Role') = 'authenticated'")).toBe("-");
    expect(gate("(auth.uid() = owner_id)")).toBe("-");
    expect(gate("true")).toBe("-");
  });
});

describe("writeReach", () => {
  const table = (policies: string): RlsTable => {
    const dir = mkdtempSync(join(tmpdir(), "auditai-write-reach-"));
    mkdirSync(join(dir, "supabase/migrations"), { recursive: true });
    writeFileSync(join(dir, "supabase/migrations/0001.sql"), `${NOTES}${policies}`);
    const t = parseProject(dir, { sqlDirs: ["supabase/migrations"] }).tables[0];
    if (!t) throw new Error("no table");
    return t;
  };

  it("reaches every row when the API accepts a change without a filter, read policy or not", () => {
    const t = table(`create policy "open update" on public.notes for update using (true);`);
    expect(writeReach(t, "anon", "update", true).reach).toBe("no-row");
    expect(writeReach(t, "anon", "update", false).reach).toBe("every-row");
    // Without safeupdate a RESTRICTIVE false on the write still refuses it.
    const frozen = table(`create policy "open update" on public.notes for update using (true);
create policy "frozen" on public.notes as restrictive for update using (false);`);
    expect(writeReach(frozen, "anon", "update", false).reach).toBe("no-row");
  });

  it("counts no read from a policy without USING, and no limit from a RESTRICTIVE one", () => {
    // Postgres keeps no condition for a policy that only has WITH CHECK (checked on 17.6).
    const checkOnly = table(`create policy "open update" on public.notes for update using (true);
create policy "anon inserts" on public.notes for all to anon with check (true);`);
    expect(writeReach(checkOnly, "anon", "update", true).reach).toBe("no-row");
    const restrictiveCheckOnly =
      table(`create policy "open update" on public.notes for update using (true);
create policy "anyone reads" on public.notes for select using (true);
create policy "shape" on public.notes as restrictive for all to anon with check (body is not null);`);
    expect(writeReach(restrictiveCheckOnly, "anon", "update", true).reach).toBe("every-row");
  });

  it("refuses an update whose every new row a RESTRICTIVE check refuses; FOR ALL only by an ALL one", () => {
    const noNewRows = table(`create policy "open update" on public.notes for update using (true);
create policy "anyone reads" on public.notes for select using (true);
create policy "frozen" on public.notes as restrictive for update with check (false);`);
    expect(writeReach(noNewRows, "anon", "update", true)).toMatchObject({ reach: "no-row" });
    expect(writeReach(noNewRows, "anon", "delete", true).reach).toBe("every-row");
    const all = table(`create policy "open" on public.notes for all using (true);
create policy "no updates" on public.notes as restrictive for update using (false);`);
    expect(writeReach(all, "anon", "all", true).reach).toBe("every-row");
  });

  it("marks what the parser cannot place: comments, concatenated names, policies made by a function, a rename", () => {
    const model = (sql: string) => {
      const dir = mkdtempSync(join(tmpdir(), "auditai-unread-"));
      mkdirSync(join(dir, "supabase/migrations"), { recursive: true });
      writeFileSync(join(dir, "supabase/migrations/0001.sql"), `${NOTES}${sql}`);
      return parseProject(dir, { sqlDirs: ["supabase/migrations"] });
    };
    // Skeptic review, round 2: each of these made a read policy the model did not hold.
    const comment = model(`do $$ begin if not exists (select 1) then
  create policy "Public read" -- shown on the landing page
    on public.notes for select using (true); end if; end $$;`);
    expect(comment.tables[0]?.policiesUnread).toBe(true);
    const concatenated = model(
      `do $$ begin execute 'create policy ' || quote_ident('p') || ' on public.notes for select using (true)'; end $$;`,
    );
    expect(concatenated.policiesUnread).toBe(true);
    const byFunction = model(`create function public.open_up() returns void language plpgsql as $$
begin create policy "Public read" on public.notes for select using (true); end $$;
select public.open_up();`);
    expect(byFunction.tables[0]?.policiesUnread).toBe(true);
    const renamed = model(`create table public.old_notes (id int primary key);
alter table public.old_notes enable row level security;
do $$ begin if true then create policy "r" on public.old_notes for select using (true); end if; end $$;
alter table public.old_notes rename to later_notes;`);
    expect(renamed.tables.find((t) => t.table === "later_notes")?.policiesUnread).toBe(true);
    // A preload list without safeupdate: the API role no longer refuses a change without a filter.
    expect(
      model("alter role authenticator set session_preload_libraries = 'supautils';")
        .dataApiRefusesUnfilteredWrites,
    ).toBe(false);
    // Nothing of the sort: nothing marked.
    const plain = model(`create policy "r" on public.notes for select using (true);`);
    expect(plain.tables[0]?.policiesUnread).toBeUndefined();
    expect(plain.policiesUnread).toBeUndefined();
  });

  it("does not count a read policy that no row passes", () => {
    const t = table(`create policy "open update" on public.notes for update using (true);
create policy "never" on public.notes for select using (false);`);
    expect(writeReach(t, "anon", "update", true).reach).toBe("no-row");
  });
});

describe("anon-write-policy on a live snapshot", () => {
  it("keeps the headline where the project switched safeupdate off", () => {
    const model = parseProject(mkdtempSync(join(tmpdir(), "auditai-empty-")), {});
    const dir = mkdtempSync(join(tmpdir(), "auditai-sql-policies-"));
    mkdirSync(join(dir, "supabase/migrations"), { recursive: true });
    writeFileSync(
      join(dir, "supabase/migrations/0001.sql"),
      `${NOTES}create policy "open update" on public.notes for update using (true);`,
    );
    const parsed = parseProject(dir, { sqlDirs: ["supabase/migrations"] });
    const run = (refuses: boolean) =>
      runRules(
        supabaseSqlPoliciesPack,
        { ...parsed, dataApiRefusesUnfilteredWrites: refuses, fromLiveDatabase: true as const },
        buildGraph(parsed),
        { now: "2026-09-24T00:00:00Z" },
      );
    expect(model.dataApiRefusesUnfilteredWrites).toBeUndefined();
    expect(run(true)[0]?.tier).toBe("lead");
    const [open] = run(false);
    expect(open?.tier).toBeUndefined();
    expect(open?.evidence[0]?.data).toMatchObject({ reach: "every-row" });
    expect(open?.evidence[0]?.summary).toContain("safeupdate is not in force");
  });
});

describe("view-runs-with-owner-rights", () => {
  const OWNED = `${NOTES}create policy "owner reads" on public.notes for select using (owner_id = auth.uid());
`;
  const of = (f: Finding[]) => f.filter((x) => x.ruleId === "supabase.view-runs-with-owner-rights");

  it("reports a view without security_invoker over a protected table, high when anon may select it", () => {
    const f = of(
      scan(`${OWNED}create view public.note_titles as select id, body from public.notes;`),
    );
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("high");
    expect(f[0]?.title).toBe('View "note_titles" shows "notes" with its owner\'s rights');
    expect(f[0]?.sinks).toEqual(["supabase.select:public.notes"]);
    expect(f[0]?.evidence[0]?.summary).toContain(
      "alter view public.note_titles set (security_invoker = on)",
    );
    expect(f[0]?.evidence[0]?.data).toMatchObject({
      deterministic: true,
      sources: ["notes"],
      anon: true,
    });
  });

  it("leaves out a view defined only outside the Supabase CLI migrations", () => {
    const cli = { "supabase/migrations/20260101000000_init.sql": OWNED };
    const f = (files: Record<string, string>) => of(scan("", { ...cli, ...files }));
    // A schema file next to the migrations may never have been applied.
    expect(
      f({ "database/views.sql": "create view public.v as select * from public.notes;" }),
    ).toEqual([]);
    // The same view in a migration is reported.
    expect(
      f({
        "supabase/migrations/20260102000000_v.sql":
          "create view public.v as select * from public.notes;",
      }),
    ).toHaveLength(1);
  });

  it("stays silent when only signed-in users reach the view and they read the whole table already", () => {
    const view = `create view public.v as select * from public.notes;
revoke select on public.v from anon;
`;
    for (const using of ["true", "auth.uid() is not null", "((select auth.uid()) is not null)"]) {
      const sql = `${NOTES}create policy "signed in read" on public.notes for select to authenticated using (${using});
${view}`;
      expect(of(scan(sql))).toEqual([]);
    }
    // Anon still reaching the view is another matter: the table is closed to anon.
    expect(
      of(
        scan(`${NOTES}create policy "signed in read" on public.notes for select to authenticated using (true);
create view public.v as select * from public.notes;`),
      ),
    ).toHaveLength(1);
  });

  it("stays silent when the view filters with the helper the table's policy uses", () => {
    const base = `${NOTES}create function public.can_view(o uuid) returns boolean language sql stable as $$ select o = auth.uid() $$;
create policy "members read" on public.notes for select using (public.can_view(owner_id));
`;
    expect(
      of(
        scan(
          `${base}create view public.v as select * from public.notes n where public.can_view(n.owner_id);`,
        ),
      ),
    ).toEqual([]);
    // Any other function in the view is no filter.
    expect(
      of(scan(`${base}create view public.v as select id, lower(body) from public.notes;`)),
    ).toHaveLength(1);
  });

  it("keeps an earlier relation when CREATE VIEW IF NOT EXISTS meets its name", () => {
    const f = of(
      scan(`${OWNED}create view public.v with (security_invoker = on) as select * from public.notes;
create materialized view if not exists public.v as select * from public.notes;`),
    );
    expect(f).toEqual([]);
  });

  it("follows migration GRANT and REVOKE of SELECT on the view", () => {
    const view = `${OWNED}create view public.v as select * from public.notes;\n`;
    // Both API roles lose SELECT: PostgREST refuses before the view runs.
    for (const sql of [
      `${view}revoke select on public.v from anon, authenticated;`,
      `${view}revoke all on table public.v from anon;\nrevoke all privileges on public.v from authenticated;`,
      `${view}revoke all on all tables in schema public from anon, authenticated;`,
    ]) {
      expect(of(scan(sql))).toEqual([]);
    }
    // Only anon loses it: signed-in users still read every row, medium.
    const signedIn = of(scan(`${view}revoke select on public.v from anon;`));
    expect(signedIn).toHaveLength(1);
    expect(signedIn[0]?.severity).toBe("medium");
    // Revoking PUBLIC leaves anon's and authenticated's own grants; a later GRANT gives SELECT back;
    // a column list is not the whole view.
    for (const sql of [
      `${view}revoke all on public.v from public;`,
      `${view}revoke select on public.v from anon, authenticated;\ngrant select on public.v to anon;`,
      `${view}revoke select (body) on public.v from anon, authenticated;`,
    ]) {
      expect(of(scan(sql))).toHaveLength(1);
    }
    // A hardening script guards the revoke with IF ... THEN inside a DO block.
    expect(
      of(
        scan(`${view}do $$ begin
  if to_regclass('public.v') is not null then
    revoke all privileges on table public.v from anon;
    revoke all privileges on table public.v from authenticated;
  end if;
end $$;`),
      ),
    ).toEqual([]);
    // A view dropped and created again starts with the default grants.
    expect(
      of(
        scan(
          `${view}revoke select on public.v from anon, authenticated;\ndrop view public.v;\ncreate view public.v as select * from public.notes;`,
        ),
      ),
    ).toHaveLength(1);
  });

  it("stays silent for security_invoker views, views over open or unprotected tables, and views over views", () => {
    for (const sql of [
      `${OWNED}create view public.v with (security_invoker = on) as select * from public.notes;`,
      `${OWNED}create view public.v as select * from public.notes;
alter view public.v set (security_invoker = true);`,
      // The table is public already: the view adds nothing.
      `${NOTES}create policy "anyone reads" on public.notes for select using (true);
create view public.v as select * from public.notes;`,
      // RLS off is the other rules' subject, not the view's.
      `create table public.open (id int);
create view public.v as select * from public.open;`,
      // A view over a view: the inner view is the finding, if any.
      `${OWNED}create view public.inner_v as select * from public.notes;
create view public.outer_v as select * from public.inner_v;`,
    ]) {
      const f = of(scan(sql));
      expect(f.length, sql).toBeLessThanOrEqual(1);
      expect(
        f.map((x) => x.evidence[0]?.data?.table),
        sql,
      ).not.toContain("outer_v");
      if (!sql.includes("inner_v")) expect(f, sql).toEqual([]);
    }
  });

  it("calls a materialized view a stored copy and tells the owner to revoke rather than switch invoker", () => {
    const f = of(
      scan(`${OWNED}create materialized view public.note_copy as select * from public.notes;`),
    );
    expect(f).toHaveLength(1);
    expect(f[0]?.evidence[0]?.summary).toContain("materialized view");
    expect(f[0]?.evidence[0]?.summary).toContain(
      "revoke select on public.note_copy from anon, authenticated",
    );
  });
});
