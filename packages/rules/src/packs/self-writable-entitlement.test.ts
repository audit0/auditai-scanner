import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildGraph } from "@auditai/graph";
import { parseProject } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { defaultRules } from "../index.js";
import { runRules } from "../rule.js";
import { selfWritableEntitlementColumn } from "./self-writable-entitlement.js";

const NOW = "2026-09-27T00:00:00Z";

function project(files: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), "auditai-entitlement-"));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  const model = parseProject(dir);
  return runRules([selfWritableEntitlementColumn], model, buildGraph(model), { now: NOW });
}

const sqlOnly = (sql: string) => project({ "supabase/migrations/20260101000000_init.sql": sql });

const BASE = `create table public.profiles (id uuid primary key, full_name text, credits int not null default 3, points int not null default 0);
alter table public.profiles enable row level security;
create policy "read own" on public.profiles for select to authenticated using (id = auth.uid());
create function public.handle_new_user() returns trigger language plpgsql security definer as $$
begin insert into public.profiles (id) values (new.id); return new; end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();
create function public.spend_credit() returns void language plpgsql security definer as $$
declare v int;
begin
  select credits into v from public.profiles where id = auth.uid() for update;
  if v <= 0 then raise exception 'no credits'; end if;
  update public.profiles set credits = credits - 1 where id = auth.uid();
end $$;
`;
const UPDATE_OWN = `create policy "update own" on public.profiles for update to authenticated using (id = auth.uid());\n`;

describe("supabase.self-writable-entitlement-column", () => {
  it("fixture 049: one finding on the vulnerable app, none on the secure one", () => {
    const scan = (variant: string) => {
      const dir = fileURLToPath(
        new URL(
          `../../../../evals/fixtures/049-self-writable-entitlement-column/${variant}/`,
          import.meta.url,
        ),
      );
      const model = parseProject(dir);
      return runRules(defaultRules, model, buildGraph(model), { now: NOW });
    };
    expect(scan("vulnerable").map((f) => [f.ruleId, f.severity, f.entrypoints])).toEqual([
      [
        selfWritableEntitlementColumn.id,
        "high",
        ["PATCH /rest/v1/profiles", "POST /api/invoices/export"],
      ],
    ]);
    expect(scan("secure")).toEqual([]);
  });

  it("reports credits a definer function decides on, under an own-row UPDATE policy", () => {
    const findings = sqlOnly(BASE + UPDATE_OWN);
    expect(findings.map((f) => [f.title, f.severity, f.status])).toEqual([
      ['Signed-in users can rewrite "profiles.credits", which the server trusts', "high", "likely"],
    ]);
    expect(findings[0]?.evidence[0]?.data).toMatchObject({
      table: "profiles",
      column: "credits",
      path: "update",
      policies: ["update own"],
    });
  });

  it("stays silent on a column nothing decides on, whatever its name", () => {
    // points is self-writable too, but no route, function or policy compares it.
    expect(sqlOnly(BASE + UPDATE_OWN).map((f) => f.evidence[0]?.data?.column)).toEqual(["credits"]);
    const onlyReturned = BASE.replace(
      /create function public\.spend_credit[\s\S]*$/,
      `create function public.my_credits() returns int language sql security definer as $$
  select credits from public.profiles where id = auth.uid() $$;
`,
    );
    expect(sqlOnly(onlyReturned + UPDATE_OWN)).toEqual([]);
  });

  it("reports game currencies at medium", () => {
    const findings = sqlOnly(
      `${BASE}create function public.enter_game() returns void language plpgsql security definer as $$
begin
  if (select points from public.profiles where id = auth.uid()) < 10 then raise exception 'x'; end if;
end $$;
${UPDATE_OWN}`,
    );
    expect(findings.map((f) => [f.evidence[0]?.data?.column, f.severity])).toEqual([
      ["credits", "high"],
      ["points", "medium"],
    ]);
  });

  it("is silent when WITH CHECK, a column privilege or a trigger holds the column", () => {
    expect(
      sqlOnly(
        `${BASE}create policy "update own" on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid() and credits = (select credits from public.profiles where id = auth.uid()));`,
      ),
    ).toEqual([]);
    expect(
      sqlOnly(
        `${BASE + UPDATE_OWN}revoke update on public.profiles from authenticated;
grant update (full_name) on public.profiles to authenticated;`,
      ),
    ).toEqual([]);
    expect(
      sqlOnly(`${BASE + UPDATE_OWN}create function public.keep_credits() returns trigger language plpgsql as $$
begin
  if new.credits is distinct from old.credits and auth.role() <> 'service_role' then raise exception 'no'; end if;
  return new;
end $$;
create trigger keep_credits before update on public.profiles for each row execute function public.keep_credits();`),
    ).toEqual([]);
  });

  it("is silent when no one ever creates the rows, and when the project does not use Supabase", () => {
    // A function that only reads credits; nothing inserts or updates profiles.
    const noRows = `create table public.profiles (id uuid primary key, full_name text, credits int not null default 3);
alter table public.profiles enable row level security;
create policy "read own" on public.profiles for select to authenticated using (id = auth.uid());
create function public.can_export() returns boolean language plpgsql security definer as $$
declare v int;
begin
  select credits into v from public.profiles where id = auth.uid();
  if v <= 0 then return false; end if;
  return true;
end $$;
`;
    expect(sqlOnly(noRows + UPDATE_OWN)).toEqual([]);
    expect(
      project({
        "supabase/migrations/20260101000000_init.sql": BASE + UPDATE_OWN,
        "package.json": JSON.stringify({ dependencies: { next: "15.0.0", pg: "8.0.0" } }),
      }),
    ).toEqual([]);
  });

  it("becomes a candidate when a SELECT policy on the table reads the table itself", () => {
    const findings = sqlOnly(
      `${BASE + UPDATE_OWN}create policy "admins read" on public.profiles for select to authenticated using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.full_name = 'admin'));`,
    );
    expect(findings.map((f) => [f.status, f.confidence])).toEqual([["candidate", 0.5]]);
  });
});
