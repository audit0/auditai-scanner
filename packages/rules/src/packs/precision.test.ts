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
