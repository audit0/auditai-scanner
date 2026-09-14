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
 * Precision round 7 (14 September 2026): causes the third blind sample showed
 * (docs/realworld/2026-09-14-blind-sample-3.md). Every accepted shape sits next to the shape that must
 * stay a finding: a comparison with a value from the request, a helper that lets everyone through, a
 * membership read that is not the caller's.
 */

const ADMIN = `import { createClient } from "@supabase/supabase-js";
export function admin() { return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!); }
`;

function scan(files: Record<string, string>): Finding[] {
  const dir = mkdtempSync(join(tmpdir(), "auditai-rules-round7-"));
  for (const [rel, text] of Object.entries({ "lib/admin.ts": ADMIN, ...files })) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  const model = parseProject(dir, { sqlDirs: ["supabase/migrations"] });
  return runRules(supabaseAuthorizationPack, model, buildGraph(model), {
    now: "2026-09-14T00:00:00Z",
  });
}

const R1 = "supabase.service-role-object-access-without-tenant-scope";
const of = (fs: Finding[], rule: string): Finding[] => fs.filter((f) => f.ruleId === rule);

describe("a helper loads the parent row and compares its organization with the caller's (getAuthorizedRequest)", () => {
  const SCHEMA = `create table public.org_members (user_id uuid not null, org_id uuid not null, role text not null);
create table public.review_requests (id uuid primary key, org_id uuid not null);
create table public.review_attachments (id uuid primary key, request_id uuid not null references public.review_requests (id));
alter table public.org_members enable row level security;
alter table public.review_requests enable row level security;
alter table public.review_attachments enable row level security;`;
  const project = (canAccessBody: string) => ({
    "supabase/migrations/0001_init.sql": SCHEMA,
    "lib/auth.ts": `import { createClient } from "@supabase/supabase-js";
import { admin } from "@/lib/admin";
export async function getApiUser() {
  const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return null;
  const { data: membership } = await admin().from("org_members").select("org_id, role").eq("user_id", user.id).single();
  if (!membership) return null;
  return { id: user.id, orgId: membership.org_id, role: membership.role };
}
export async function canAccessRequest(user: { orgId: string; role: string }, requestOrgId: string, asked: string) {
${canAccessBody}
}
export async function getAuthorizedRequest(requestId: string, user: { orgId: string; role: string }, asked: string) {
  const { data: request } = await admin().from("review_requests").select("*").eq("id", requestId).single();
  if (!request) return null;
  const allowed = await canAccessRequest(user, request.org_id, asked);
  if (!allowed) return null;
  return request;
}
`,
    "app/api/requests/[id]/route.ts": `import { admin } from "@/lib/admin";
import { getApiUser, getAuthorizedRequest } from "@/lib/auth";
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await getApiUser();
  if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });
  const { id } = await params;
  const asked = new URL(req.url).searchParams.get("org") ?? "";
  const request = await getAuthorizedRequest(id, user, asked);
  if (!request) return Response.json({ error: "Not found" }, { status: 404 });
  const { data } = await admin().from("review_attachments").select("*").eq("request_id", id);
  return Response.json({ request, attachments: data });
}
`,
  });

  it("counts a helper whose every path compares the row with the caller as the ownership check", () => {
    expect(of(scan(project("  return user.orgId === requestOrgId;")), R1)).toEqual([]);
    expect(
      of(scan(project("  if (requestOrgId !== user.orgId) return false;\n  return true;")), R1),
    ).toEqual([]);
  });

  it("lowers, never drops, a comparison a role of the caller skips", () => {
    const findings = of(
      scan(
        project(
          '  if (user.role === "reviewer" || user.role === "admin") {\n    return true;\n  }\n  return user.orgId === requestOrgId;',
        ),
      ),
      R1,
    );
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.severity).toBe("medium");
      expect(f.title).toContain("(verify the role exception)");
      expect(f.evidence[0]?.summary).toContain('user.role === "reviewer" || user.role === "admin"');
    }
  });

  it("keeps the finding when the helper compares with the request, lets everyone through, or only has the name", () => {
    for (const body of [
      "  return requestOrgId === asked;",
      "  return true;",
      "  return Boolean(requestOrgId);",
      '  if (asked === "all") return true;\n  return user.orgId === requestOrgId;',
    ]) {
      const findings = of(scan(project(body)), R1);
      expect(findings.length, body).toBeGreaterThan(0);
      expect(
        findings.every((f) => f.severity === "critical"),
        body,
      ).toBe(true);
    }
  });
});

describe("a membership read by the caller and by the loaded row's organization (roadmaps)", () => {
  const SCHEMA = `create table public.roadmaps (id uuid primary key, organisation_id uuid not null, title text);
create table public.organisation_members (user_id uuid not null, organisation_id uuid not null);
alter table public.roadmaps enable row level security;
alter table public.organisation_members enable row level security;`;
  const route = (memberFilter: string) => ({
    "supabase/migrations/0001_init.sql": SCHEMA,
    "app/api/roadmaps/[id]/route.ts": `import { createClient } from "@supabase/supabase-js";
import { admin } from "@/lib/admin";
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return Response.json({ error: "Unauthorised" }, { status: 401 });
  const { id } = await params;
  const result = await admin().from("roadmaps").select("*").eq("id", id).single();
  const { data: roadmap } = result;
  if (!roadmap) return Response.json({ error: "Not found" }, { status: 404 });
  const { data: membership } = await admin().from("organisation_members").select("organisation_id")${memberFilter}.maybeSingle();
  if (!membership) return Response.json({ error: "Not found" }, { status: 404 });
  await admin().from("roadmaps").delete().eq("id", id);
  return Response.json({ ok: true });
}
`,
  });

  it("counts the membership read as the ownership check", () => {
    expect(
      of(scan(route('.eq("user_id", user.id).eq("organisation_id", roadmap.organisation_id)')), R1),
    ).toEqual([]);
  });

  it("keeps the finding when the membership read is not the caller's or not the row's organization", () => {
    for (const filter of [
      '.eq("user_id", user.id).eq("organisation_id", new URL(req.url).searchParams.get("org"))',
      '.eq("organisation_id", roadmap.organisation_id)',
    ]) {
      expect(of(scan(route(filter)), R1).length, filter).toBeGreaterThan(0);
    }
  });
});
