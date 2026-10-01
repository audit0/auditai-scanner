import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildGraph } from "@auditai/graph";
import { parseProject } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { defaultRules } from "../index.js";
import { runRules } from "../rule.js";
import { roleFromSignupMetadata } from "./role-from-signup-metadata.js";

const NOW = "2026-09-26T00:00:00Z";

function sqlOnly(sql: string) {
  const dir = mkdtempSync(join(tmpdir(), "auditai-signup-role-"));
  const rel = "supabase/migrations/20260101000000_init.sql";
  mkdirSync(dirname(join(dir, rel)), { recursive: true });
  writeFileSync(join(dir, rel), sql);
  const model = parseProject(dir);
  return runRules([roleFromSignupMetadata], model, buildGraph(model), { now: NOW });
}

const BASE = `create table public.profiles (id uuid primary key, role text default 'member', full_name text);
alter table public.profiles enable row level security;
create policy "read own" on public.profiles for select using (id = auth.uid());
create function public.is_admin() returns boolean language sql security definer as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin') $$;
`;
const handler = (value: string) => `create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, role, full_name)
  values (new.id, ${value}, new.raw_user_meta_data ->> 'full_name');
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();
`;

describe("supabase.role-from-signup-metadata", () => {
  it("fixture 048: one finding on the vulnerable app, none on the secure one", () => {
    const scan = (variant: string) => {
      const dir = fileURLToPath(
        new URL(
          `../../../../evals/fixtures/048-role-from-signup-metadata/${variant}/`,
          import.meta.url,
        ),
      );
      const model = parseProject(dir);
      return runRules(defaultRules, model, buildGraph(model), { now: NOW });
    };
    expect(scan("vulnerable").map((f) => [f.ruleId, f.severity])).toEqual([
      [roleFromSignupMetadata.id, "critical"],
    ]);
    expect(scan("secure")).toEqual([]);
  });

  it("reports a role copied unchanged, and not the display name next to it", () => {
    const findings = sqlOnly(
      BASE + handler("coalesce(new.raw_user_meta_data ->> 'role', 'member')"),
    );
    expect(findings.map((f) => [f.title, f.entrypoints])).toEqual([
      [
        'Sign-up metadata "role" becomes "profiles.role", which grants privileges',
        ["POST /auth/v1/signup"],
      ],
    ]);
  });

  it("is silent on an allow-list, a BEFORE INSERT guard, a persona enum or a function no trigger runs", () => {
    const allowList = handler(
      "case when new.raw_user_meta_data ->> 'role' in ('member', 'viewer') then new.raw_user_meta_data ->> 'role' else 'member' end",
    );
    expect(sqlOnly(BASE + allowList)).toEqual([]);
    const guard = `${handler("new.raw_user_meta_data ->> 'role'")}
create function public.force_member() returns trigger language plpgsql as $$
begin new.role := 'member'; return new; end $$;
create trigger force_member before insert on public.profiles for each row execute function public.force_member();`;
    expect(sqlOnly(BASE + guard)).toEqual([]);
    const persona = `create type public.persona as enum ('buyer', 'seller');
create table public.profiles (id uuid primary key, role public.persona, full_name text);
alter table public.profiles enable row level security;
create policy "read own" on public.profiles for select using (id = auth.uid());
create policy "sellers" on public.profiles for select using ((select role from public.profiles where id = auth.uid()) = 'seller');
${handler("(new.raw_user_meta_data ->> 'role')::public.persona")}`;
    expect(sqlOnly(persona)).toEqual([]);
    const noTrigger =
      BASE + handler("new.raw_user_meta_data ->> 'role'").replace(/create trigger[\s\S]*$/, "");
    expect(sqlOnly(noTrigger)).toEqual([]);
  });

  it("is silent when nothing reads the column as a privilege", () => {
    const sql = `create table public.profiles (id uuid primary key, role text);
alter table public.profiles enable row level security;
${handler("new.raw_user_meta_data ->> 'role'")}`;
    expect(sqlOnly(sql)).toEqual([]);
  });

  describe("tenant column", () => {
    const TENANT = `create table public.orgs (id uuid primary key, name text);
create table public.user_profiles (id uuid primary key, organisation_id uuid, full_name text);
create table public.incidents (id uuid primary key, organisation_id uuid, note text);
alter table public.user_profiles enable row level security;
alter table public.incidents enable row level security;
create function public.get_my_organisation_id() returns uuid language sql stable security definer as $$
  select organisation_id from public.user_profiles where id = auth.uid() $$;
create policy "org members read" on public.incidents for select
  using (organisation_id = public.get_my_organisation_id());
`;
    const signup = (value: string) => `create function public.handle_new_auth_user() returns trigger
language plpgsql security definer as $$
declare v_org uuid;
begin
  v_org := ${value};
  insert into public.user_profiles (id, organisation_id) values (new.id, v_org);
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_auth_user();
`;

    it("reports a tenant id copied from sign-up metadata that the policies scope by", () => {
      const findings = sqlOnly(
        TENANT + signup("(new.raw_user_meta_data ->> 'organisation_id')::uuid"),
      );
      expect(
        findings.map((f) => [f.evidence[0]?.data?.kind, f.evidence[0]?.data?.column, f.severity]),
      ).toEqual([["tenant", "organisation_id", "high"]]);
      expect(findings[0]?.title).toContain("the tenant the policies scope by");
    });

    it("is silent when no policy scopes by the column, or a BEFORE INSERT trigger checks it", () => {
      const unscoped = TENANT.replace(/create policy[\s\S]*$/, "");
      expect(
        sqlOnly(unscoped + signup("(new.raw_user_meta_data ->> 'organisation_id')::uuid")),
      ).toEqual([]);
      const checked = `${TENANT + signup("(new.raw_user_meta_data ->> 'organisation_id')::uuid")}
create function public.check_invite() returns trigger language plpgsql as $$
begin
  if not exists (select 1 from public.invites i where i.email = new.email and i.org = new.organisation_id)
  then raise exception 'no invitation'; end if;
  return new;
end $$;
create trigger check_invite before insert on public.user_profiles for each row execute function public.check_invite();`;
      expect(sqlOnly(checked)).toEqual([]);
    });
  });

  it("marks a role copy a candidate when every reader of the column recurses, not when a definer helper reads it", () => {
    const recursiveOnly = `create table public.profiles (id uuid primary key, role text default 'member');
alter table public.profiles enable row level security;
create policy "admins read all" on public.profiles for select
  using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin'));
${handler("coalesce(new.raw_user_meta_data ->> 'role', 'member')").replace(", full_name", "").replace(", new.raw_user_meta_data ->> 'full_name'", "")}`;
    expect(sqlOnly(recursiveOnly).map((f) => f.status)).toEqual(["candidate"]);
    const withHelper = `${recursiveOnly}
create function public.is_admin() returns boolean language sql security definer as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin') $$;
create table public.notes (id uuid primary key);
alter table public.notes enable row level security;
create policy "admins" on public.notes for all using (public.is_admin());`;
    expect(sqlOnly(withHelper).map((f) => f.status)).toEqual(["likely"]);
  });
});
