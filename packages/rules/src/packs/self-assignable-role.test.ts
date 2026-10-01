import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildGraph } from "@auditai/graph";
import { parseProject } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { defaultRules } from "../index.js";
import { runRules } from "../rule.js";
import { selfAssignableRoleColumn } from "./self-assignable-role.js";

const NOW = "2026-09-26T00:00:00Z";

function project(files: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), "auditai-self-role-"));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  const model = parseProject(dir);
  return runRules([selfAssignableRoleColumn], model, buildGraph(model), { now: NOW });
}

const sqlOnly = (sql: string) => project({ "supabase/migrations/20260101000000_init.sql": sql });

const BASE = `create table public.profiles (id uuid primary key, full_name text, role text default 'member');
alter table public.profiles enable row level security;
create policy "read own" on public.profiles for select to authenticated using (id = auth.uid());
create function public.is_admin() returns boolean language sql security definer as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin') $$;
create function public.handle_new_user() returns trigger language plpgsql security definer as $$
begin insert into public.profiles (id) values (new.id); return new; end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();
`;
const UPDATE_OWN = `create policy "update own" on public.profiles for update to authenticated using (id = auth.uid());\n`;

describe("supabase.self-assignable-role-column", () => {
  it("fixture 047: one finding on the vulnerable app, none on the secure one", () => {
    const scan = (variant: string) => {
      const dir = fileURLToPath(
        new URL(
          `../../../../evals/fixtures/047-self-assignable-role-column/${variant}/`,
          import.meta.url,
        ),
      );
      const model = parseProject(dir);
      return runRules(defaultRules, model, buildGraph(model), { now: NOW });
    };
    expect(scan("vulnerable").map((f) => [f.ruleId, f.severity])).toEqual([
      [selfAssignableRoleColumn.id, "critical"],
    ]);
    expect(scan("secure")).toEqual([]);
  });

  it("reports an own-row UPDATE policy that leaves an is_admin() column free", () => {
    const findings = sqlOnly(BASE + UPDATE_OWN);
    expect(findings.map((f) => [f.title, f.entrypoints])).toEqual([
      [
        'Signed-in users can rewrite "profiles.role", which grants privileges',
        ["PATCH /rest/v1/profiles"],
      ],
    ]);
    expect(findings[0]?.evidence[0]?.data).toMatchObject({
      path: "update",
      policies: ["update own"],
    });
  });

  it("reads the privilege from a policy expression too", () => {
    const findings = sqlOnly(`create table public.profiles (id uuid primary key, role text);
alter table public.profiles enable row level security;
create table public.reports (id uuid primary key);
alter table public.reports enable row level security;
create policy "admins read" on public.reports for select using ((select role from public.profiles where id = auth.uid()) = 'admin');
create policy "own" on public.profiles for all to authenticated using (id = auth.uid());`);
    expect(findings).toHaveLength(1);
  });

  it("is silent when WITH CHECK, a column privilege, a trigger or a restrictive policy holds the column", () => {
    const withCheck = `create policy "update own" on public.profiles for update to authenticated using (id = auth.uid())
  with check (id = auth.uid() and role = (select p.role from public.profiles p where p.id = auth.uid()));`;
    const grants = `${UPDATE_OWN}revoke update on public.profiles from authenticated;
grant update (full_name) on public.profiles to authenticated;`;
    const trigger = `${UPDATE_OWN}create function public.keep_role() returns trigger language plpgsql as $$
begin if new.role is distinct from old.role then raise exception 'no'; end if; return new; end $$;
create trigger keep_role before update on public.profiles for each row execute function public.keep_role();`;
    const restrictive = `${UPDATE_OWN}create policy "role fixed" on public.profiles as restrictive for update
  with check (role = 'member');`;
    for (const extra of [withCheck, grants, trigger, restrictive])
      expect(sqlOnly(BASE + extra)).toEqual([]);
  });

  it("does not conclude from a policy an ALTER POLICY changed, but still from an untouched one", () => {
    const altered = `${UPDATE_OWN}alter policy "update own" on public.profiles using (id = auth.uid()) with check (role = 'member');`;
    expect(sqlOnly(BASE + altered)).toEqual([]);
    const second = `${altered}\ncreate policy "soft delete" on public.profiles for update using (auth.uid() = id);`;
    expect(sqlOnly(BASE + second).map((f) => f.evidence[0]?.data?.policies)).toEqual([
      ["soft delete"],
    ]);
  });

  it("does not read an admin check about another row as an own-row policy", () => {
    const findings =
      sqlOnly(`${BASE}create table public.members (id uuid primary key, user_id uuid, role text);
alter table public.members enable row level security;
create policy "admins manage" on public.members for all to authenticated
  using (exists (select 1 from public.profiles where profiles.id = auth.uid() and 'admin' = any (array[profiles.role])));
create policy "read" on public.members for select using (true);
create function public.is_member_admin() returns boolean language sql security definer as $$
  select exists (select 1 from public.members where user_id = auth.uid() and role = 'admin') $$;`);
    expect(findings).toEqual([]);
    const self =
      sqlOnly(`${BASE}create table public.members (id uuid primary key, user_id uuid, owner_id uuid, role text);
alter table public.members enable row level security;
create policy "read" on public.members for select using (true);
create policy "join" on public.members for insert to authenticated
  with check (user_id = auth.uid() and role = 'member');
create policy "own membership" on public.members for update to authenticated
  using (owner_id = auth.uid() or user_id = (select auth.uid()));
create function public.is_member_admin() returns boolean language sql security definer as $$
  select exists (select 1 from public.members where user_id = auth.uid() and role = 'admin') $$;`);
    expect(self.map((f) => f.evidence[0]?.data?.column)).toEqual(["role"]);
  });

  it("does not trust a SECURITY DEFINER guard that returns unless current_user is a signed-in role", () => {
    const guard = (
      definer: string,
    ) => `${UPDATE_OWN}create function public.keep_role() returns trigger
language plpgsql ${definer} set search_path = public as $$
declare v_email text := auth.jwt() ->> 'email';
begin
  if current_user not in ('authenticated', 'anon') then return new; end if;
  if new.role is distinct from old.role then raise exception 'no'; end if;
  return new;
end $$;
create trigger keep_role before update on public.profiles for each row execute function public.keep_role();`;
    const findings = sqlOnly(BASE + guard("security definer"));
    expect(findings.map((f) => f.evidence[0]?.data?.inertTriggers)).toEqual([["keep_role"]]);
    expect(findings[0]?.evidence[0]?.summary).toContain("current_user is the function's owner");
    expect(sqlOnly(BASE + guard("security invoker"))).toEqual([]);
  });

  it("finds delete-and-reinsert when a trigger only watches UPDATE", () => {
    const findings =
      sqlOnly(`${BASE}create policy "own" on public.profiles for all to authenticated using (id = auth.uid());
create function public.keep_role() returns trigger language plpgsql as $$
begin if new.role is distinct from old.role then raise exception 'no'; end if; return new; end $$;
create trigger keep_role before update on public.profiles for each row execute function public.keep_role();`);
    expect(findings.map((f) => [f.evidence[0]?.data?.path, f.entrypoints[0]])).toEqual([
      ["reinsert", "DELETE + POST /rest/v1/profiles"],
    ]);
  });

  it("is silent without a privilege source, without RLS, or when the row cannot be read", () => {
    const noSource = `create table public.profiles (id uuid primary key, role text);
alter table public.profiles enable row level security;
create policy "read own" on public.profiles for select using (id = auth.uid());
${UPDATE_OWN}`;
    expect(sqlOnly(noSource)).toEqual([]);
    const unreadable = BASE.replace(/create policy "read own"[^\n]*\n/, "") + UPDATE_OWN;
    expect(sqlOnly(unreadable)).toEqual([]);
    expect(
      sqlOnly(BASE.replace("enable row level security", "disable row level security") + UPDATE_OWN),
    ).toEqual([]);
  });

  it("reads the role check of a route handler", () => {
    const findings = project({
      "supabase/migrations/20260101000000_init.sql": `create table public.profiles (id uuid primary key, role text);
alter table public.profiles enable row level security;
create policy "own" on public.profiles for all to authenticated using (id = auth.uid());`,
      "app/api/admin/route.ts": `import { createClient } from "@supabase/supabase-js";
export async function GET(req: Request) {
  const supabase = createClient("u", "k", { global: { headers: { Authorization: req.headers.get("authorization") ?? "" } } });
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response(null, { status: 401 });
  const { data: profile } = await supabase.from("profiles").select("role").eq("id", user.id).single();
  if (profile?.role !== "admin") return new Response(null, { status: 403 });
  return Response.json({ ok: true });
}`,
    });
    expect(findings.map((f) => f.entrypoints)).toEqual([
      ["PATCH /rest/v1/profiles", "GET /api/admin"],
    ]);
  });

  it("is silent when the user never has a row, or when no package.json depends on Supabase", () => {
    const noRows = BASE.replace(/create function public\.handle_new_user[\s\S]*$/, "") + UPDATE_OWN;
    expect(sqlOnly(noRows)).toEqual([]);
    const serviceInsert = project({
      "supabase/migrations/20260101000000_init.sql": noRows,
      "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "^2" } }),
      "app/api/members/route.ts": `import { createClient } from "@supabase/supabase-js";
export async function POST(req: Request) {
  const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
  const body = await req.json();
  await admin.from("profiles").insert({ id: body.id });
  return new Response(null, { status: 201 });
}`,
    });
    expect(serviceInsert.map((f) => f.ruleId)).toEqual(["supabase.self-assignable-role-column"]);
    const leftover = project({
      "supabase/migrations/20260101000000_init.sql": BASE + UPDATE_OWN,
      "package.json": JSON.stringify({ dependencies: { "drizzle-orm": "^0.45", next: "15" } }),
    });
    expect(leftover).toEqual([]);
  });

  it("keeps a finding on a table whose SELECT policy recurses, as a candidate with the caveat", () => {
    const recursive = `${BASE + UPDATE_OWN}create policy "admins read all" on public.profiles for select
  using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin'));`;
    const [f] = sqlOnly(recursive);
    expect(f?.status).toBe("candidate");
    expect(f?.evidence[0]?.data?.recursivePolicies).toEqual(["admins read all"]);
    expect(f?.evidence[0]?.summary).toContain("42P17");
    expect(sqlOnly(BASE + UPDATE_OWN)[0]?.status).toBe("likely");
  });
});
