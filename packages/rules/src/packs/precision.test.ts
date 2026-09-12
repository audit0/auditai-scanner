import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Finding } from "@auditai/core";
import { buildGraph } from "@auditai/graph";
import { parseProject } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { runRules } from "../rule.js";
import {
  isAuthzMetadataRead,
  metadataField,
  supabaseAuthorizationPack,
} from "./supabase-authorization.js";

/** Rule-level checks for the precision fixes of the 12 September 2026 real-world run. */

const ADMIN = `import { createClient } from "@supabase/supabase-js";
export function admin() { return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!); }
`;
const SCHEMA = `create table public.docs (id uuid primary key, tenant_id uuid not null, title text);
alter table public.docs enable row level security;
create policy "docs: tenant read" on public.docs for select to authenticated using (tenant_id = auth.uid());`;

function scan(files: Record<string, string>): Finding[] {
  const dir = mkdtempSync(join(tmpdir(), "auditai-rules-precision-"));
  const all = { "lib/admin.ts": ADMIN, "supabase/migrations/0001.sql": SCHEMA, ...files };
  for (const [rel, text] of Object.entries(all)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  const model = parseProject(dir, { sqlDirs: ["supabase/migrations"] });
  return runRules(supabaseAuthorizationPack, model, buildGraph(model), {
    now: "2026-09-12T00:00:00Z",
  });
}

const rules = (fs: Finding[]): string[] => fs.map((f) => f.ruleId.replace("supabase.", "")).sort();

describe("R5 reads the metadata field, not the variable holding the user", () => {
  it("extracts the field from the path", () => {
    expect(metadataField({ path: "adminCtx.user.user_metadata?.full_name" })).toBe("full_name");
    expect(metadataField({ path: "user.user_metadata.role" })).toBe("role");
    expect(isAuthzMetadataRead({ path: "adminCtx.user.user_metadata?.full_name" })).toBe(false);
    expect(isAuthzMetadataRead({ path: "x", field: "is_admin" })).toBe(true);
  });

  it("stays silent on a display name read through a variable called adminCtx (DeskcommCRM)", () => {
    const f = scan({
      "app/api/admin/tenants/route.ts": `export async function POST(req: Request) {
  const adminCtx = await getAdminContext(req);
  const actor = adminCtx.user.user_metadata?.full_name;
  return Response.json({ actor });
}`,
    });
    expect(rules(f)).not.toContain("role-check-from-user-metadata");
  });

  it("still flags a role read from user_metadata", () => {
    const f = scan({
      "app/api/admin/tenants/route.ts": `export async function POST(req: Request) {
  const adminCtx = await getAdminContext(req);
  if (adminCtx.user.user_metadata?.role !== "admin") return new Response("no", { status: 403 });
  return Response.json({ ok: true });
}`,
    });
    expect(rules(f)).toContain("role-check-from-user-metadata");
  });
});

describe("custom authentication and operator endpoints", () => {
  const CRON = `import { admin } from "@/lib/admin";
export async function POST(req: Request) {
  if (req.headers.get("authorization") !== \`Bearer \${process.env.CRON_SECRET}\`) {
    return new Response("Unauthorized", { status: 401 });
  }
  const { id, tenant_id } = await req.json();
  await admin().from("docs").delete().eq("id", id);
  await admin().from("docs").select("*").eq("tenant_id", tenant_id);
}`;

  it("a cron route that checks the secret is neither unauthenticated nor a cross-tenant access", () => {
    expect(scan({ "app/api/cron/purge/route.ts": CRON })).toEqual([]);
  });

  it("the same route without the secret check is flagged", () => {
    const f = scan({
      "app/api/cron/purge/route.ts": CRON.replace(/ {2}if \(req[\s\S]*?\n {2}\}\n/, ""),
    });
    expect(rules(f)).toEqual([
      "service-role-object-access-without-tenant-scope",
      "service-role-query-without-authentication",
      "user-controlled-tenant-scope",
    ]);
  });

  it("a user session next to the secret keeps the tenant rules on (not operator-only)", () => {
    const f = scan({
      "app/api/cron/purge/route.ts": CRON.replace(
        "const { id, tenant_id } = await req.json();",
        'const { id, tenant_id } = await req.json();\n  await admin().auth.getUser(req.headers.get("x-user-token") ?? "");',
      ),
    });
    expect(rules(f)).toEqual([
      "service-role-object-access-without-tenant-scope",
      "user-controlled-tenant-scope",
    ]);
  });

  it("a helper merely named requireAuth does not authenticate", () => {
    const f = scan({
      "lib/guard.ts": `export async function requireAuth(request: Request) { return request.headers.get("x-user"); }`,
      "app/api/admin/docs/route.ts": `import { admin } from "@/lib/admin";
import { requireAuth } from "@/lib/guard";
export async function GET(request: Request) {
  await requireAuth(request);
  return Response.json(await admin().from("docs").select("*"));
}`,
    });
    expect(rules(f)).toEqual(["service-role-query-without-authentication"]);
  });
});

describe("R1 ownership checked by an earlier guard read (wacrm requireOwnership)", () => {
  const USER = `import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
export async function createClient() {
  const store = await cookies();
  return createServerClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!, {
    cookies: { getAll: () => store.getAll(), setAll: () => {} },
  });
}`;
  const route = (
    guardExits: boolean,
    guardClient: "createClient" | "admin",
  ) => `import { admin } from "@/lib/admin";
import { createClient } from "@/lib/supabase-server";
async function requireOwnership(docId: string) {
  const supabase = ${guardClient === "createClient" ? "await createClient()" : "admin()"};
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return { ok: false as const, status: 401 };
  const { data: doc } = await supabase.from("docs").select("id").eq("id", docId).maybeSingle();
  ${guardExits ? "if (!doc) return { ok: false as const, status: 404 };" : "// no check on a missing row"}
  return { ok: true as const };
}
export async function DELETE(_req: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const guard = await requireOwnership(id);
  if (!guard.ok) return new Response("no", { status: guard.status });
  const { error } = await admin().from("docs").delete().eq("id", id);
  return Response.json({ ok: !error });
}`;

  it("treats the service-role delete as scoped when the guard read is RLS-scoped and stops on a missing row", () => {
    const f = scan({
      "lib/supabase-server.ts": USER,
      "app/api/docs/[id]/route.ts": route(true, "createClient"),
    });
    expect(rules(f)).toEqual([]);
  });

  it("keeps the finding when nothing stops the handler on a missing row, and says why", () => {
    const f = scan({
      "lib/supabase-server.ts": USER,
      "app/api/docs/[id]/route.ts": route(false, "createClient"),
    });
    const r1 = f.filter(
      (x) => x.ruleId === "supabase.service-role-object-access-without-tenant-scope",
    );
    expect(r1).toHaveLength(1);
    expect(r1[0]?.evidence[0]?.summary).toContain('An earlier read of the same "id"');
    expect(r1[0]?.evidence[0]?.summary).toContain("does not stop when it finds no row");
    expect(r1[0]?.path.some((s) => s.includes("guard read at"))).toBe(true);
  });

  it("does not accept a guard read that runs with the service role itself", () => {
    const f = scan({
      "lib/supabase-server.ts": USER,
      "app/api/docs/[id]/route.ts": route(true, "admin"),
    });
    expect(rules(f)).toContain("service-role-object-access-without-tenant-scope");
  });
});

describe("R1 ownership established by the shapes of fixture 036 (13 September 2026 labels)", () => {
  const SESSION = `import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
export async function currentUser() {
  const store = await cookies();
  const supabase = createServerClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!, {
    cookies: { getAll: () => store.getAll(), setAll: () => {} },
  });
  const { data: { user } } = await supabase.auth.getUser();
  return user;
}
export async function userClient() {
  const store = await cookies();
  return createServerClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!, {
    cookies: { getAll: () => store.getAll(), setAll: () => {} },
  });
}`;
  const SCHEMA_FK = `create table public.projects (id uuid primary key, owner_id uuid not null, name text);
create table public.tasks (id uuid primary key, project_id uuid not null references public.projects (id), title text);
create table public.docs (id uuid primary key, tenant_id uuid not null, title text);
alter table public.projects enable row level security;
alter table public.tasks enable row level security;
alter table public.docs enable row level security;`;
  const r1 = "service-role-object-access-without-tenant-scope";
  const scanWith = (route: string): Finding[] =>
    scan({
      "lib/session.ts": SESSION,
      "supabase/migrations/0001.sql": SCHEMA_FK,
      "app/api/x/[id]/route.ts": `import { admin } from "@/lib/admin";
import { currentUser, userClient } from "@/lib/session";
export async function GET(req: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const user = await currentUser();
  if (!user) return new Response("no", { status: 401 });
${route}
}`,
    });

  it("accepts a guard read of the parent row (foreign key) that is owner-filtered and stops", () => {
    const f =
      scanWith(`  const { data: project } = await admin().from("projects").select("id").eq("id", id).eq("owner_id", user.id).maybeSingle();
  if (!project) return new Response("no", { status: 404 });
  const { data } = await admin().from("tasks").select("*").eq("project_id", id);
  return Response.json(data);`);
    expect(rules(f)).not.toContain(r1);
  });

  it("accepts the parent link by column name too (automation_steps.automation_id -> automations)", () => {
    const f =
      scanWith(`  const { data: automation } = await admin().from("automations").select("id").eq("id", id).eq("user_id", user.id).maybeSingle();
  if (!automation) return new Response("no", { status: 404 });
  const { data } = await admin().from("automation_steps").select("*").eq("automation_id", id);
  return Response.json(data);`);
    expect(rules(f)).not.toContain(r1);
  });

  it("keeps the finding when the parent read cannot be tied to the caller, and names the parent row", () => {
    // Through the cookie client, but projects has RLS with no select policy: nothing scopes the read.
    const f = scanWith(`  const sb = await userClient();
  const { data: project } = await sb.from("projects").select("id").eq("id", id).maybeSingle();
  if (!project) return new Response("no", { status: 404 });
  const { data } = await admin().from("tasks").select("*").eq("project_id", id);
  return Response.json(data);`);
    const hits = f.filter((x) => x.ruleId === `supabase.${r1}`);
    expect(hits.map((h) => h.sinks[0])).toEqual(["supabase.select:public.tasks"]);
    expect(hits[0]?.evidence[0]?.summary).toContain(
      "the parent row projects.id (tasks.project_id refers to it by foreign key)",
    );
    expect(hits[0]?.evidence[0]?.summary).toContain("could not be shown to tie rows");
    // A service-role parent read with no owner filter proves nothing and is not mentioned.
    const silent =
      scanWith(`  const { data: project } = await admin().from("projects").select("id").eq("id", id).maybeSingle();
  if (!project) return new Response("no", { status: 404 });
  const { data } = await admin().from("tasks").select("*").eq("project_id", id);
  return Response.json(data);`);
    const sinks = silent.filter((x) => x.ruleId === `supabase.${r1}`).map((h) => h.sinks[0]);
    expect(sinks.sort()).toEqual([
      "supabase.select:public.projects",
      "supabase.select:public.tasks",
    ]);
  });

  it("accepts an owner comparison in code after the read, for the read and for later writes", () => {
    const f =
      scanWith(`  const { data: existing } = await admin().from("docs").select("id, tenant_id").eq("id", id).maybeSingle();
  if (!existing || existing.tenant_id !== user.app_metadata.tenant_id) return new Response("no", { status: 404 });
  await admin().from("docs").update({ title: "x" }).eq("id", id);
  return Response.json({ ok: true });`);
    expect(rules(f)).not.toContain(r1);
  });

  it("rejects an owner comparison against a request value, or one that does not stop the route", () => {
    const fromBody = scanWith(`  const { tenant } = await req.json();
  const { data: existing } = await admin().from("docs").select("id, tenant_id").eq("id", id).maybeSingle();
  if (!existing || existing.tenant_id !== tenant) return new Response("no", { status: 404 });
  await admin().from("docs").update({ title: "x" }).eq("id", id);`);
    expect(rules(fromBody).filter((r) => r === r1)).toHaveLength(2);
    const noExit =
      scanWith(`  const { data: existing } = await admin().from("docs").select("id, tenant_id").eq("id", id).maybeSingle();
  if (!existing || existing.tenant_id !== user.app_metadata.tenant_id) console.warn("foreign");
  await admin().from("docs").update({ title: "x" }).eq("id", id);`);
    expect(rules(noExit).filter((r) => r === r1)).toHaveLength(2);
  });

  it("accepts a conditional owner filter on a query builder when the caller cannot steer the condition", () => {
    const f = scanWith(`  let query = admin().from("docs").select("*").eq("id", id);
  if (user.app_metadata?.role !== "admin") query = query.eq("tenant_id", user.app_metadata.tenant_id);
  const { data } = await query.maybeSingle();
  return Response.json(data);`);
    expect(rules(f)).not.toContain(r1);
  });

  it("rejects a conditional owner filter whose condition comes from the request", () => {
    const f = scanWith(`  let query = admin().from("docs").select("*").eq("id", id);
  if (!new URL(req.url).searchParams.get("all")) query = query.eq("tenant_id", user.app_metadata.tenant_id);
  const { data } = await query.maybeSingle();
  return Response.json(data);`);
    expect(rules(f)).toContain(r1);
  });
});

describe("ADR-001: single-tenant admin console (pasal isAdminEmail)", () => {
  const SESSION = `import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
export async function createClient() {
  const store = await cookies();
  return createServerClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!, {
    cookies: { getAll: () => store.getAll(), setAll: () => {} },
  });
}`;
  const ADMIN_AUTH = `export const ADMIN_EMAILS = (process.env.ADMIN_EMAILS ?? "").split(",");
export function isAdminEmail(email: string | undefined | null): boolean {
  return !!email && ADMIN_EMAILS.includes(email.toLowerCase());
}`;
  const r1 = "supabase.service-role-object-access-without-tenant-scope";
  const route = (gate: string) => `import { admin } from "@/lib/admin";
import { createClient } from "@/lib/supabase-server";
import { isAdminEmail } from "@/lib/admin-auth";
export async function PATCH(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  ${gate}
  const { id } = await params;
  await admin().from("works").update({ status: "x" }).eq("id", id);
  return Response.json({ ok: true });
}`;
  const files = (schema: string, gate: string) => ({
    "lib/supabase-server.ts": SESSION,
    "lib/admin-auth.ts": ADMIN_AUTH,
    "supabase/migrations/0001.sql": schema,
    "app/api/admin/works/[id]/route.ts": route(gate),
  });
  const SINGLE = `create table public.works (id serial primary key, title text, status text);
alter table public.works enable row level security;`;
  const TENANT = `create table public.works (id serial primary key, owner_id uuid not null, title text);
alter table public.works enable row level security;`;
  const GATE = `if (!user || !isAdminEmail(user.email)) return new Response("no", { status: 401 });`;

  it("lowers R1 to medium on a single-tenant table behind an evidence-based admin gate, and says what to verify", () => {
    const f = scan(files(SINGLE, GATE)).filter((x) => x.ruleId === r1);
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("medium");
    expect(f[0]?.status).toBe("likely");
    expect(f[0]?.title).toContain("Admin-only");
    expect(f[0]?.evidence[0]?.summary).toContain("verify the admin check cannot be self-granted");
    expect(f[0]?.evidence[0]?.summary).toContain("user.email");
    expect(f[0]?.evidence[0]?.data).toMatchObject({ adminOnly: true, roleCheck: "user.email" });
  });

  it("keeps critical when the table has an owner column, when the role comes from user_metadata, or when the table is unknown", () => {
    const tenant = scan(files(TENANT, GATE)).filter((x) => x.ruleId === r1);
    expect(tenant.map((x) => x.severity)).toEqual(["critical"]);
    // A child of a tenant's table is a tenant's row one hop away (wacrm broadcast_recipients).
    const child = `create table public.broadcasts (id uuid primary key, account_id uuid not null);
create table public.works (id serial primary key, broadcast_id uuid not null references public.broadcasts (id), title text);
alter table public.works enable row level security;`;
    expect(scan(files(child, GATE)).find((x) => x.ruleId === r1)?.severity).toBe("critical");
    const meta = scan(
      files(
        SINGLE,
        `if (!user || user.user_metadata?.role !== "admin") return new Response("no", { status: 401 });`,
      ),
    );
    expect(meta.find((x) => x.ruleId === r1)?.severity).toBe("critical");
    expect(rules(meta)).toContain("role-check-from-user-metadata");
    const unknown = scan(files("select 1;", GATE)).filter((x) => x.ruleId === r1);
    expect(unknown.map((x) => x.severity)).toEqual(["critical"]);
    const noGate = scan(
      files(SINGLE, `if (!user) return new Response("no", { status: 401 });`),
    ).filter((x) => x.ruleId === r1);
    expect(noGate.map((x) => x.severity)).toEqual(["critical"]);
  });
});

describe("ADR-002: public-by-design tables", () => {
  const r7 = "supabase.service-role-query-without-authentication";
  const r3 = "supabase.rls-policy-without-caller-predicate";
  const CATALOG = `create table public.products (id uuid primary key, name text, price_cents integer);
create table public.orders (id uuid primary key, user_id uuid not null, total integer);
alter table public.products enable row level security;
alter table public.orders enable row level security;`;
  const READ = `import { admin } from "@/lib/admin";
export async function GET() {
  const { data } = await admin().from("products").select("*").order("name");
  return Response.json(data);
}`;
  const WRITE = `import { admin } from "@/lib/admin";
export async function POST(req: Request) {
  const { name } = await req.json();
  await admin().from("products").insert({ name });
  return Response.json({ ok: true });
}`;
  const MIXED = `import { admin } from "@/lib/admin";
export async function GET() {
  const { data: products } = await admin().from("products").select("*");
  const { data: orders } = await admin().from("orders").select("*");
  return Response.json({ products, orders });
}`;
  const scanPublic = (files: Record<string, string>, publicTables: string[]): Finding[] => {
    const dir = mkdtempSync(join(tmpdir(), "auditai-rules-public-"));
    const all = { "lib/admin.ts": ADMIN, "supabase/migrations/0001.sql": CATALOG, ...files };
    for (const [rel, text] of Object.entries(all)) {
      mkdirSync(dirname(join(dir, rel)), { recursive: true });
      writeFileSync(join(dir, rel), text);
    }
    const model = parseProject(dir, { sqlDirs: ["supabase/migrations"] });
    return runRules(supabaseAuthorizationPack, model, buildGraph(model), {
      now: "2026-09-13T00:00:00Z",
      publicTables,
    });
  };

  it("suppresses a read-only R7 on a declared table with the declaration as the reason", () => {
    const f = scanPublic({ "app/api/products/route.ts": READ }, ["products"]);
    expect(f.map((x) => [x.ruleId, x.status])).toEqual([[r7, "suppressed"]]);
    expect(f[0]?.evidence.at(-1)?.summary).toContain("declared public in audit.config.json");
    expect(f[0]?.evidence.at(-1)?.data).toMatchObject({
      suppressed: true,
      publicTables: ["products"],
    });
  });

  it("never covers a write path, an undeclared table next to a declared one, or R1", () => {
    const write = scanPublic({ "app/api/products/route.ts": WRITE }, ["products"]);
    expect(write.map((x) => [x.ruleId, x.status])).toEqual([[r7, "likely"]]);
    const mixed = scanPublic({ "app/api/catalog/route.ts": MIXED }, ["products"]);
    expect(mixed.map((x) => [x.ruleId, x.status])).toEqual([[r7, "likely"]]);
    const byId = scanPublic(
      {
        "app/api/products/[id]/route.ts": `import { admin } from "@/lib/admin";
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { data } = await admin().from("products").select("*").eq("id", id).maybeSingle();
  return Response.json(data);
}`,
      },
      ["products"],
    );
    expect(byId.map((x) => [x.ruleId.replace("supabase.", ""), x.status])).toEqual([
      ["service-role-object-access-without-tenant-scope", "likely"],
    ]);
  });

  it("suppresses a select policy finding on a declared table but not a for-all policy", () => {
    const USER = `import { createClient } from "@supabase/supabase-js";
export function anon() { return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!); }`;
    const ROUTE = `import { anon } from "@/lib/anon";
export async function GET() {
  const { data } = await anon().from("orders").select("*");
  return Response.json(data);
}`;
    const selectPolicy = `${CATALOG}
create policy "orders: everyone reads" on public.orders for select using (true);`;
    const allPolicy = `${CATALOG}
create policy "orders: everyone everything" on public.orders for all using (true);`;
    const sel = scanPublic(
      {
        "lib/anon.ts": USER,
        "app/api/orders/route.ts": ROUTE,
        "supabase/migrations/0001.sql": selectPolicy,
      },
      ["orders"],
    );
    expect(sel.map((x) => [x.ruleId, x.status])).toEqual([[r3, "suppressed"]]);
    const all = scanPublic(
      {
        "lib/anon.ts": USER,
        "app/api/orders/route.ts": ROUTE,
        "supabase/migrations/0001.sql": allPolicy,
      },
      ["orders"],
    );
    expect(all.map((x) => [x.ruleId, x.status])).toEqual([[r3, "likely"]]);
  });

  it("without a declaration, a public read of a table anon can already read in full is medium, citing the policy", () => {
    const policy = `${CATALOG}
create policy "Public can view products" on public.products for select using (true);`;
    const f = scanPublic(
      { "app/api/products/route.ts": READ, "supabase/migrations/0001.sql": policy },
      [],
    );
    expect(f.map((x) => [x.ruleId, x.status, x.severity])).toEqual([[r7, "likely", "medium"]]);
    expect(f[0]?.evidence[0]?.summary).toContain('RLS policy "Public can view products"');
    // R1 on the same table: a read by id leaks nothing beyond anon either.
    const byId = scanPublic(
      {
        "app/api/products/[id]/route.ts": `import { admin } from "@/lib/admin";
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { data } = await admin().from("products").select("*").eq("id", id).maybeSingle();
  return Response.json(data);
}`,
        "supabase/migrations/0001.sql": policy,
      },
      [],
    );
    expect(byId.map((x) => [x.ruleId.replace("supabase.", ""), x.severity])).toEqual([
      ["service-role-object-access-without-tenant-scope", "medium"],
    ]);
  });

  it("keeps critical when the policy is for authenticated only, has a predicate, or the table has none", () => {
    const authOnly = `${CATALOG}
create policy "signed-in read products" on public.products for select to authenticated using (true);`;
    const predicate = `${CATALOG}
create policy "published products" on public.products for select using (price_cents > 0);`;
    for (const sql of [authOnly, predicate, CATALOG]) {
      const f = scanPublic(
        { "app/api/products/route.ts": READ, "supabase/migrations/0001.sql": sql },
        [],
      );
      expect(f.map((x) => [x.ruleId, x.severity])).toEqual([[r7, "critical"]]);
    }
  });
});

describe("R8 mass assignment only for whole request objects", () => {
  it("ignores rows rebuilt with explicit fields and keeps a spread of the body", () => {
    const f = scan({
      "app/api/docs/route.ts": `import { admin } from "@/lib/admin";
export async function POST(req: Request) {
  const { data: { user } } = await admin().auth.getUser(req.headers.get("authorization") ?? "");
  const { items } = await req.json();
  const rows = items.map((it) => ({ title: it.title, tenant_id: user!.id }));
  await admin().from("docs").insert(rows);
  await admin().from("docs").insert(items.map((it) => ({ ...it, tenant_id: user!.id })));
}`,
    });
    const mass = f.filter((x) => x.ruleId === "supabase.mass-assignment-from-request-body");
    expect(mass).toHaveLength(1);
    expect(mass[0]?.path[2]).toContain("...it");
  });
});
