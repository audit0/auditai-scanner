import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Finding } from "@auditai/core";
import { buildGraph } from "@auditai/graph";
import { parseProject } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { runRules } from "../rule.js";
import { supabaseAuthorizationPack } from "./supabase-authorization.js";

/**
 * Precision round 5 (13 September 2026): the causes the blind sample still showed after round 4
 * (docs/realworld/2026-09-13-round-4.md). Every accepted shape sits next to the shape that must stay
 * a finding: a value from the request, a constant, a role column its owner can rewrite.
 */

const ADMIN = `import { createClient } from "@supabase/supabase-js";
export function admin() { return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!); }
`;

function scan(files: Record<string, string>): Finding[] {
  const dir = mkdtempSync(join(tmpdir(), "auditai-rules-identity-"));
  for (const [rel, text] of Object.entries({ "lib/admin.ts": ADMIN, ...files })) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  const model = parseProject(dir, { sqlDirs: ["supabase/migrations"] });
  return runRules(supabaseAuthorizationPack, model, buildGraph(model), {
    now: "2026-09-13T00:00:00Z",
  });
}

const R1 = "supabase.service-role-object-access-without-tenant-scope";
const R8 = "supabase.mass-assignment-from-request-body";
const of = (fs: Finding[], rule: string): Finding[] => fs.filter((f) => f.ruleId === rule);

describe("a row the caller's identity selected scopes what it filters (git-city developers)", () => {
  const SCHEMA = `create table public.developers (id bigint generated always as identity primary key, claimed_by uuid, name text);
create table public.portfolio_experiences (id uuid primary key, developer_id bigint not null references public.developers (id), company text);
alter table public.developers enable row level security;
alter table public.portfolio_experiences enable row level security;`;
  const portfolio = (lookup: string, scope: string) => ({
    "supabase/migrations/0001.sql": SCHEMA,
    "app/api/portfolio/[id]/route.ts": `import { createClient } from "@supabase/supabase-js";
import { admin } from "@/lib/admin";
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const body = await req.json();
  const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("no", { status: 401 });
${lookup}
  if (!dev) return new Response("no", { status: 404 });
  const { data: existing } = await admin().from("portfolio_experiences").select("id").eq("id", id).eq("developer_id", ${scope}).single();
  if (!existing) return new Response("no", { status: 404 });
  await admin().from("portfolio_experiences").update({ company: String(body.company) }).eq("id", id);
  return Response.json({ ok: true });
}`,
  });
  const BY_SESSION = `  const { data: dev } = await admin().from("developers").select("id").eq("claimed_by", user.id).single();`;
  const BY_REQUEST = `  const { data: dev } = await admin().from("developers").select("id").eq("claimed_by", body.user_id).single();`;
  const ASSIGNED = `  let dev: { id: number } | null = null;
  {
    const { data } = await admin().from("developers").select("id").eq("claimed_by", user.id).maybeSingle();
    dev = data;
  }`;

  it("treats a filter by the caller's own developer row as the owner scope", () => {
    expect(of(scan(portfolio(BY_SESSION, "dev.id")), R1)).toEqual([]);
  });

  it("follows the row through an assignment to an outer variable", () => {
    expect(of(scan(portfolio(ASSIGNED, "dev.id")), R1)).toEqual([]);
  });

  it("keeps the finding when the scope value or the lookup comes from the request", () => {
    expect(of(scan(portfolio(BY_SESSION, "body.developer_id")), R1).length).toBeGreaterThan(0);
    expect(of(scan(portfolio(BY_REQUEST, "dev.id")), R1).length).toBeGreaterThan(0);
  });
});

describe("an owner compared in code through an embedded relation (git-city advertisers)", () => {
  const SCHEMA = `create table public.advertiser_accounts (id uuid primary key, email text);
create table public.advertiser_sessions (id uuid primary key, token text not null, advertiser_id uuid not null references public.advertiser_accounts (id), expires_at timestamptz);
create table public.job_company_profiles (id uuid primary key, advertiser_id uuid not null references public.advertiser_accounts (id), name text);
create table public.job_listings (id uuid primary key, company_id uuid not null references public.job_company_profiles (id), status text);
alter table public.job_listings enable row level security;`;
  const AUTH = `import { cookies } from "next/headers";
import { admin } from "@/lib/admin";
export async function getAdvertiserFromCookies() {
  const store = await cookies();
  const token = store.get("adv_session")?.value;
  if (!token) return null;
  return getAdvertiserBySessionToken(token);
}
export async function getAdvertiserBySessionToken(token: string) {
  const { data: session } = await admin()
    .from("advertiser_sessions")
    .select("expires_at, advertiser:advertiser_accounts!inner(id, email)")
    .eq("token", token)
    .maybeSingle();
  if (!session) return null;
  const adv = session.advertiser as unknown as { id: string; email: string };
  return adv ?? null;
}`;
  const manage = (compare: string) => ({
    "supabase/migrations/0001.sql": SCHEMA,
    "lib/advertiser-auth.ts": AUTH,
    "app/api/jobs/[id]/manage/route.ts": `import { admin } from "@/lib/admin";
import { getAdvertiserFromCookies } from "@/lib/advertiser-auth";
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const body = await req.json();
  const advertiser = await getAdvertiserFromCookies();
  if (!advertiser) return new Response("no", { status: 401 });
  const { data: listing } = await admin()
    .from("job_listings")
    .select("id, company:job_company_profiles!inner(id, advertiser_id)")
    .eq("id", id)
    .single();
  if (!listing) return new Response("no", { status: 404 });
  const comp = listing.company as unknown as { id: string; advertiser_id: string };
  if (${compare}) return new Response("not yours", { status: 403 });
  await admin().from("job_listings").update({ status: "paused" }).eq("id", id);
  return Response.json({ ok: true, note: body.note });
}`,
  });

  it("counts the comparison with the account a session token authenticated", () => {
    expect(of(scan(manage("comp.advertiser_id !== advertiser.id")), R1)).toEqual([]);
  });

  it("keeps the finding when the row is compared with the request or with a constant", () => {
    expect(
      of(scan(manage("comp.advertiser_id !== body.advertiser_id")), R1).length,
    ).toBeGreaterThan(0);
    expect(of(scan(manage(`comp.id !== "c1"`)), R1).length).toBeGreaterThan(0);
  });
});

describe("ADR-001 with the role read from the caller's own profile row (klubb-app ensureAdmin)", () => {
  const AUTH = `import { createClient } from "@supabase/supabase-js";
function kanAdministrere(rolle: string | undefined | null): boolean {
  return rolle === "admin";
}
export async function ensureAdmin() {
  const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) throw new Error("no session");
  const { data: profil, error } = await supabase.from("profiles").select("rolle").eq("id", user.id).maybeSingle();
  if (error) throw new Error(error.message);
  if (!kanAdministrere(profil?.rolle)) throw new Error("not admin");
  return { supabase, user, profil };
}`;
  const ACTION = `"use server";
import { admin } from "@/lib/admin";
import { ensureAdmin } from "@/lib/auth";
export async function slettNyhet(id: string) {
  await ensureAdmin();
  await admin().from("nyheter").delete().eq("id", id);
}`;
  const TABLES = `create table public.profiles (id uuid primary key, rolle text not null default 'medlem');
alter table public.profiles enable row level security;
create policy "read" on public.profiles for select using (true);
create table public.nyheter (id uuid primary key, tittel text);
alter table public.nyheter enable row level security;`;
  const SELF_UPDATE = `create policy "own row or admin" on public.profiles for update using (id = auth.uid());`;
  const TRIGGER = `create or replace function public.beskytt_profil_kolonner() returns trigger language plpgsql security definer as $$
begin
  if new.rolle is distinct from old.rolle then raise exception 'only admins change rolle'; end if;
  return new;
end;
$$;
create trigger beskytt_profil_kolonner before update on public.profiles for each row execute function public.beskytt_profil_kolonner();`;
  const files = (...sql: string[]) => ({
    "supabase/migrations/0001.sql": [TABLES, ...sql].join("\n"),
    "lib/auth.ts": AUTH,
    "app/admin/actions.ts": ACTION,
  });

  it("lowers R1 to medium when no policy lets a user rewrite the role column", () => {
    const f = of(scan(files()), R1);
    expect(f.map((x) => x.severity)).toEqual(["medium"]);
    expect(f[0]?.evidence[0]?.data).toMatchObject({ adminOnly: true, roleCheck: "profil.rolle" });
  });

  it("lowers it too when the owner may update the row but a trigger guards the role column", () => {
    expect(of(scan(files(SELF_UPDATE, TRIGGER)), R1).map((x) => x.severity)).toEqual(["medium"]);
  });

  it("keeps critical, and says why, when the owner may update the row and nothing guards the role", () => {
    const f = of(scan(files(SELF_UPDATE)), R1);
    expect(f.map((x) => x.severity)).toEqual(["critical"]);
    expect(f[0]?.evidence[0]?.summary).toContain("public.profiles.rolle");
    expect(f[0]?.evidence[0]?.summary).toContain("own row or admin");
  });
});

describe("R8 through a client that RLS still binds (africatechjobs, lugo)", () => {
  const route = (table: string, client: string) => ({
    "app/api/items/route.ts": `import { createClient } from "@supabase/supabase-js";
import { admin } from "@/lib/admin";
export async function POST(req: Request) {
  const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
  const body = await req.json();
  await ${client}.from("${table}").insert(body);
  return Response.json({ ok: supabase !== null });
}`,
  });
  const severities = (table: string, client: string, schema: string): string[] =>
    of(scan({ ...route(table, client), "supabase/migrations/0001.sql": schema }), R8).map(
      (x) => x.severity,
    );
  const OWNED = `create table public.imoveis (id uuid primary key, proprietario_id uuid not null, titulo text);
alter table public.imoveis enable row level security;
create policy "own insert" on public.imoveis for insert with check (proprietario_id = auth.uid());`;

  it("drops it when RLS refuses the write: no policy allows that command", () => {
    const schema = `create table public.jobs (id uuid primary key, title text, status text);
alter table public.jobs enable row level security;
create policy "read" on public.jobs for select using (true);`;
    expect(severities("jobs", "supabase", schema)).toEqual([]);
  });

  it("lowers it to medium when the policy pins the row to the caller and no sensitive column is left", () => {
    const f = of(
      scan({ ...route("imoveis", "supabase"), "supabase/migrations/0001.sql": OWNED }),
      R8,
    );
    expect(f.map((x) => x.severity)).toEqual(["medium"]);
    expect(f[0]?.evidence[0]?.summary).toContain("own insert");
  });

  it("keeps high with a sensitive column, an open policy, RLS off, or the service role", () => {
    const withStatus = `create table public.imoveis (id uuid primary key, proprietario_id uuid not null, titulo text, status text);
alter table public.imoveis enable row level security;
create policy "own insert" on public.imoveis for insert with check (proprietario_id = auth.uid());`;
    expect(severities("imoveis", "supabase", withStatus)).toEqual(["high"]);
    const open = `create table public.imoveis (id uuid primary key, proprietario_id uuid not null, titulo text);
alter table public.imoveis enable row level security;
create policy "open" on public.imoveis for insert with check (true);`;
    expect(severities("imoveis", "supabase", open)).toEqual(["high"]);
    const rlsOff = `create table public.imoveis (id uuid primary key, proprietario_id uuid not null, titulo text);`;
    expect(severities("imoveis", "supabase", rlsOff)).toEqual(["high"]);
    expect(severities("imoveis", "admin()", OWNED)).toEqual(["high"]);
  });
});
