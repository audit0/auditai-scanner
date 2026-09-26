import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { buildGraph } from "@auditai/graph";
import { parseProject } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { runRules } from "../rule.js";
import { userControlledTenantScope } from "./supabase-authorization.js";

/**
 * Round 8, class D: a tenant the request names, checked in code against the caller's own
 * membership. Three reviews found vulnerable shapes the check was taken to clear, so fix 3 cut that
 * path: a membership check in code clears nothing, and the lookup keyed by the caller's own id is
 * reported like any other tenant read, as on main. Every shape below, the ones that looked secure
 * included, stays a finding at the severity main gives it.
 */

const LIB = `import { createClient } from "@supabase/supabase-js";
export function admin() { return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!); }
export async function getUser(req: Request) {
  const { data } = await admin().auth.getUser(req.headers.get("authorization") ?? "");
  return data.user;
}
export async function listArticles(organizationId: string) {
  return admin().from("articles").select("*").eq("organization_id", organizationId);
}
export async function viaOne(id: string) { return viaTwo(id); }
async function viaTwo(id: string) { return viaThree(id); }
async function viaThree(id: string) { return listArticles(id); }
`;

/**
 * The membership table is defined with RLS on and no policy that lets anyone write it, so a row found
 * by the caller's own id proves membership (CE8 below covers a table the caller can write).
 */
const MEMBERS_SCHEMA = `create table public.organization_members (
  organization_id uuid not null,
  user_id uuid not null references auth.users (id) on delete cascade,
  role text not null default 'member',
  primary key (organization_id, user_id)
);
alter table public.organization_members enable row level security;
create policy "members: read own rows" on public.organization_members for select to authenticated using (user_id = auth.uid());
`;

/** R4 findings of one POST handler with this body: the query lines they point at. */
function r4Lines(handlerBody: string): number[] {
  const dir = mkdtempSync(join(tmpdir(), "auditai-ownership-in-code-"));
  const files: Record<string, string> = {
    "lib/supabase.ts": LIB,
    "supabase/migrations/0001_members.sql": MEMBERS_SCHEMA,
    "app/api/articles/route.ts": `import { admin, getUser, listArticles, viaOne } from "@/lib/supabase";
export async function POST(req: Request) {
  const user = await getUser(req);
  if (!user) return new Response(null, { status: 401 });
  const body = await req.json();
  const orgId = body.organization_id as string;
${handlerBody}
  return new Response(null);
}
`,
  };
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  const model = parseProject(dir);
  return runRules([userControlledTenantScope], model, buildGraph(model), {
    now: "2026-09-23T00:00:00Z",
  })
    .flatMap((f) => f.evidence.flatMap((e) => e.locations?.slice(1, 2) ?? []))
    .map((l) => (l.file === "lib/supabase.ts" ? -l.line : l.line - 6))
    .sort((a, b) => a - b);
}

const MEMBER = `const { data: member } = await admin().from("organization_members").select("role").eq("organization_id", orgId).eq("user_id", user.id).maybeSingle();`;
const QUERY = `await admin().from("articles").select("*").eq("organization_id", orgId);`;

describe("a tenant checked against the caller's own membership", () => {
  it("reports the membership lookup itself: the caller's own id does not clear the tenant", () => {
    expect(r4Lines(`  ${MEMBER}`)).toEqual([1]);
    // Keyed by a user id the request sends, it finds anyone's row.
    expect(
      r4Lines(
        `  await admin().from("organization_members").select("role").eq("organization_id", orgId).eq("user_id", body.user_id).maybeSingle();`,
      ),
    ).toEqual([1]);
  });

  it("reports a query the check dominates, in the handler and through a helper", () => {
    expect(
      r4Lines(`  ${MEMBER}
  if (!member) return new Response(null, { status: 403 });
  ${QUERY}
  await listArticles(orgId);`),
    ).toEqual([-8, 1, 3]);
  });

  it("keeps the query that runs before the check, or on a path that skips it", () => {
    expect(
      r4Lines(`  ${QUERY}
  ${MEMBER}
  if (!member) return new Response(null, { status: 403 });`),
    ).toEqual([1, 2]);
    // The check stands in a branch of its own; the query after the branch runs without it.
    expect(
      r4Lines(`  if (body.strict) {
    ${MEMBER}
    if (!member) return new Response(null, { status: 403 });
  }
  ${QUERY}`),
    ).toEqual([2, 5]);
  });

  it("keeps the query when the stop does not always stop, or the caller can skip it", () => {
    expect(
      r4Lines(`  ${MEMBER}
  if (!member) console.warn("not a member");
  ${QUERY}`),
    ).toEqual([1, 3]);
    expect(
      r4Lines(`  ${MEMBER}
  if (!member && !body.force) return new Response(null, { status: 403 });
  ${QUERY}`),
    ).toEqual([1, 3]);
  });

  it("keeps the query when another branch's read shares the row's name", () => {
    // The refuted spec: a membership read inside its own refusal branch silenced another branch.
    // Since the second review, a row name bound twice anywhere in the function (here `member` in
    // each branch) proves nothing even in the branch whose check does dominate: the helper's query
    // (-8) stays a finding too.
    expect(
      r4Lines(`  if (body.action === "create") {
    ${MEMBER}
    if (!member) return new Response(null, { status: 403 });
    await listArticles(orgId);
  } else {
    const { data: member } = await admin().from("projects").select("id").eq("id", body.project_id).maybeSingle();
    if (!member) return new Response(null, { status: 404 });
    ${QUERY}
  }`),
    ).toEqual([-8, 2, 8]);
  });

  it("keeps the query when the stop tests a second binding of the row's name", () => {
    expect(
      r4Lines(`  ${MEMBER}
  {
    const member = { role: "guest" };
    if (!member) return new Response(null, { status: 403 });
    ${QUERY}
  }`),
    ).toEqual([1, 5]);
    // A second var of the name between the read and the stop replaces the row.
    expect(
      r4Lines(`  var { data: member } = await admin().from("organization_members").select("role").eq("organization_id", orgId).eq("user_id", user.id).maybeSingle();
  var member = { role: "guest" };
  if (!member) return new Response(null, { status: 403 });
  ${QUERY}`),
    ).toEqual([1, 4]);
  });

  it("keeps the query when the tenant is written through or re-pointed after the check", () => {
    const check = `  const { data: m } = await admin().from("organization_members").select("role").eq("organization_id", body.organization_id).eq("user_id", user.id).maybeSingle();
  if (!m) return new Response(null, { status: 403 });`;
    const read = `  await admin().from("articles").select("*").eq("organization_id", body.organization_id);`;
    expect(r4Lines(`${check}\n${read}`)).toEqual([1, 3]);
    expect(r4Lines(`${check}\n  body.organization_id = body.other_org;\n${read}`)).toEqual([1, 4]);
    // Through a helper: the argument is a name the caller re-points before the call.
    expect(
      r4Lines(`  ${MEMBER}
  if (!member) return new Response(null, { status: 403 });
  let target = orgId;
  if (body.other_org) target = body.other_org;
  await listArticles(target);`),
    ).toEqual([-8, 1]);
  });

  it("keeps a helper's query that a second call reaches without the check", () => {
    // The same helper with the same bindings, once behind the check and once in a branch without it.
    expect(
      r4Lines(`  if (body.action === "list") {
    ${MEMBER}
    if (!member) return new Response(null, { status: 403 });
    await listArticles(orgId);
  } else {
    await listArticles(orgId);
  }`),
    ).toEqual([-8, 2]);
  });

  it("keeps a helper's query that a call chain too deep to follow reaches without the check", () => {
    // viaOne -> viaTwo -> viaThree -> listArticles: the last call lies beyond the depth the parser
    // follows, so nothing proves that path, and the check before the direct call does not cover it.
    expect(
      r4Lines(`  await viaOne(orgId);
  ${MEMBER}
  if (!member) return new Response(null, { status: 403 });
  await listArticles(orgId);`),
    ).toEqual([-8, 2]);
  });

  it("keeps the query when the check read another column or no caller id", () => {
    expect(
      r4Lines(`  const { data: project } = await admin().from("projects").select("id").eq("name", orgId).eq("user_id", user.id).maybeSingle();
  if (!project) return new Response(null, { status: 404 });
  ${QUERY}`),
    ).toEqual([3]);
    expect(
      r4Lines(`  const { data: org } = await admin().from("organizations").select("id").eq("organization_id", orgId).maybeSingle();
  if (!org) return new Response(null, { status: 404 });
  ${QUERY}`),
    ).toEqual([1, 3]);
  });
});

/*
 * The first review of this change built eight handlers the branch silenced completely while main
 * reported each one (scratchpad verify-W2/ce, ce8 and ce11). They are kept here verbatim, with the
 * schema they were scanned against, so none of them can go quiet again.
 */

const CE_LIB = `import { createClient } from "@supabase/supabase-js";
export function createServiceRoleClient() {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
    { auth: { persistSession: false } },
  );
}
export async function getUserFromRequest(req: Request) {
  const auth = req.headers.get("authorization") ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return null;
  const { data, error } = await createServiceRoleClient().auth.getUser(token);
  if (error || !data.user) return null;
  return data.user;
}
`;

/** Members may read their own rows and nothing else: no one can write a membership row. */
const CE_SCHEMA = `create table public.organizations (id uuid primary key default gen_random_uuid(), name text not null);
create table public.organization_members (
  organization_id uuid not null references public.organizations (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  role text not null default 'member',
  primary key (organization_id, user_id)
);
create table public.projects (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  owner_id uuid references auth.users (id),
  name text not null,
  created_at timestamptz not null default now()
);
alter table public.organizations enable row level security;
alter table public.organization_members enable row level security;
alter table public.projects enable row level security;
create policy "members: read own rows" on public.organization_members for select to authenticated using (user_id = auth.uid());
`;

/** CE8: anyone signed in adds themselves to any organization. */
const JOIN_POLICY = `create policy "members: join" on public.organization_members
  for insert to authenticated
  with check (user_id = auth.uid());
`;

/** Written the way rank-brnd writes it: a new row needs an owner's row for the same organization. */
const OWNERS_POLICY = `create policy "owners manage members" on public.organization_members
  for all to authenticated
  using (exists (select 1 from public.organization_members as om
    where om.organization_id = organization_members.organization_id and om.user_id = auth.uid()::text and om.role = 'owner'))
  with check (exists (select 1 from public.organization_members as om
    where om.organization_id = organization_members.organization_id and om.user_id = auth.uid()::text and om.role = 'owner'));
`;

interface R4Hit {
  table: string;
  line: number;
  severity: string;
}

/** R4 findings of one route file scanned with a schema: the table, the query line, the severity. */
function r4In(route: string, sql: string | null = CE_SCHEMA): R4Hit[] {
  const dir = mkdtempSync(join(tmpdir(), "auditai-ownership-ce-"));
  const files: Record<string, string> = {
    "lib/supabase.ts": CE_LIB,
    "app/api/ce/route.ts": route,
    ...(sql === null ? {} : { "supabase/migrations/0001_init.sql": sql }),
  };
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  const model = parseProject(dir);
  return runRules([userControlledTenantScope], model, buildGraph(model), {
    now: "2026-09-23T00:00:00Z",
  })
    .map((f) => ({
      table: (f.sinks[0] ?? "").replace(/^.*public\./, ""),
      line: f.evidence[0]?.locations?.[1]?.line ?? 0,
      severity: f.severity,
    }))
    .sort((a, b) => a.line - b.line);
}

describe("counterexamples of the first review stay findings", () => {
  it("CE1: `!members` on an array read never stops a stranger", () => {
    // [] is truthy: the check passes for everyone, so the read of projects is any organization's.
    expect(
      r4In(`import { NextResponse } from "next/server";
import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";

export async function GET(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const orgId = new URL(req.url).searchParams.get("org");
  if (!orgId) return NextResponse.json({ error: "org is required" }, { status: 400 });
  const admin = createServiceRoleClient();
  const { data: members } = await admin
    .from("organization_members")
    .select("role")
    .eq("organization_id", orgId)
    .eq("user_id", user.id);
  if (!members) return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  const { data } = await admin.from("projects").select("*").eq("organization_id", orgId);
  return NextResponse.json({ projects: data });
}
`),
    ).toEqual([
      {
        line: 10,
        severity: "critical",
        table: "organization_members",
      },
      {
        line: 16,
        severity: "critical",
        table: "projects",
      },
    ]);
  });

  it("CE1, twin: an array read whose emptiness is tested is reported as well", () => {
    for (const stop of ["!members?.length", "members.length === 0", "!members[0]"]) {
      expect(
        r4In(`import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";
export async function GET(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) return new Response(null, { status: 401 });
  const orgId = new URL(req.url).searchParams.get("org");
  const admin = createServiceRoleClient();
  const { data: members } = await admin.from("organization_members").select("role").eq("organization_id", orgId).eq("user_id", user.id);
  if (${stop}) return new Response(null, { status: 403 });
  const { data } = await admin.from("projects").select("*").eq("organization_id", orgId);
  return Response.json(data);
}
`),
      ).toEqual([
        {
          line: 7,
          severity: "critical",
          table: "organization_members",
        },
        {
          line: 9,
          severity: "critical",
          table: "projects",
        },
      ]);
    }
  });

  it("CE12: `!membership` tests the whole PostgREST response, which is always truthy", () => {
    expect(
      r4In(`import { NextResponse } from "next/server";
import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";

// The whole response object is tested, and a PostgREST response is always truthy.
export async function GET(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const orgId = new URL(req.url).searchParams.get("org");
  if (!orgId) return NextResponse.json({ error: "org is required" }, { status: 400 });
  const admin = createServiceRoleClient();
  const membership = await admin
    .from("organization_members")
    .select("role")
    .eq("organization_id", orgId)
    .eq("user_id", user.id)
    .maybeSingle();
  if (!membership) return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  const { data } = await admin.from("projects").select("*").eq("organization_id", orgId);
  return NextResponse.json({ projects: data });
}
`),
    ).toEqual([
      {
        line: 11,
        severity: "critical",
        table: "organization_members",
      },
      {
        line: 18,
        severity: "critical",
        table: "projects",
      },
    ]);
  });

  it("CE2: an identity filter added under an `if` does not make the rows the caller's own", () => {
    expect(
      r4In(`import { NextResponse } from "next/server";
import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";

export async function GET(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const orgId = new URL(req.url).searchParams.get("org");
  if (!orgId) return NextResponse.json({ error: "org is required" }, { status: 400 });
  const admin = createServiceRoleClient();
  // The caller's role in the organization they belong to (any one of them).
  const { data: mine } = await admin
    .from("organization_members")
    .select("role")
    .eq("user_id", user.id)
    .limit(1)
    .maybeSingle();
  let q = admin.from("projects").select("*").eq("organization_id", orgId);
  if (mine?.role !== "owner") q = q.eq("owner_id", user.id);
  const { data } = await q;
  return NextResponse.json({ projects: data });
}
`),
    ).toEqual([
      {
        line: 17,
        severity: "critical",
        table: "projects",
      },
    ]);
  });

  it("CE8: a membership row the caller can insert for any organization stays critical", () => {
    const route = `import { NextResponse } from "next/server";
import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";

// GET /api/projects?org=<uuid> — the organization comes from the query string, but every path to the
// read passes the caller's own membership row for it first.
export async function GET(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const url = new URL(req.url);
  const orgId = url.searchParams.get("org");
  if (!orgId) return NextResponse.json({ error: "org is required" }, { status: 400 });

  const admin = createServiceRoleClient();
  const { data: member } = await admin
    .from("organization_members")
    .select("role")
    .eq("organization_id", orgId)
    .eq("user_id", user.id)
    .maybeSingle();
  if (!member) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const { data, error } = await admin
    .from("projects")
    .select("*")
    .eq("organization_id", orgId)
    .order("created_at");
  if (error) return NextResponse.json({ error: "Failed" }, { status: 500 });
  return NextResponse.json({ projects: data });
}
`;
    expect(r4In(route, CE_SCHEMA + JOIN_POLICY)).toEqual([
      {
        line: 15,
        severity: "critical",
        table: "organization_members",
      },
      {
        line: 23,
        severity: "critical",
        table: "projects",
      },
    ]);
    // Nothing in the migrations says who may write the membership table: lowered as well.
    expect(r4In(route, null)).toEqual([
      {
        line: 15,
        severity: "critical",
        table: "organization_members",
      },
      {
        line: 23,
        severity: "critical",
        table: "projects",
      },
    ]);
    // The secure twin: RLS on, and no policy lets anyone write a membership row.
    expect(r4In(route)).toEqual([
      {
        line: 15,
        severity: "critical",
        table: "organization_members",
      },
      {
        line: 23,
        severity: "critical",
        table: "projects",
      },
    ]);
    // Owners may add members, but only to an organization they already own.
    expect(r4In(route, CE_SCHEMA + OWNERS_POLICY)).toEqual([
      {
        line: 15,
        severity: "critical",
        table: "organization_members",
      },
      {
        line: 23,
        severity: "critical",
        table: "projects",
      },
    ]);
  });

  it("CE9: a tenant variable re-pointed after the check is not the one checked", () => {
    expect(
      r4In(`import { NextResponse } from "next/server";
import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";

// The membership is checked for ?org=, then the tenant variable is re-pointed at ?compare= before the read.
export async function GET(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const url = new URL(req.url);
  let orgId = url.searchParams.get("org");
  if (!orgId) return NextResponse.json({ error: "org is required" }, { status: 400 });
  const admin = createServiceRoleClient();
  const { data: member } = await admin
    .from("organization_members")
    .select("role")
    .eq("organization_id", orgId)
    .eq("user_id", user.id)
    .maybeSingle();
  if (!member) return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  const compare = url.searchParams.get("compare");
  if (compare) orgId = compare;
  const { data } = await admin.from("projects").select("*").eq("organization_id", orgId);
  return NextResponse.json({ projects: data });
}
`),
    ).toEqual([
      {
        line: 12,
        severity: "critical",
        table: "organization_members",
      },
      {
        line: 21,
        severity: "critical",
        table: "projects",
      },
    ]);
  });

  it("CE10: a loop variable that shadows the checked tenant is another value", () => {
    expect(
      r4In(`import { NextResponse } from "next/server";
import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";

// Membership is checked for body.orgId; the loop below shadows orgId with every id the caller lists.
export async function POST(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const body = await req.json();
  const orgId: string = body.orgId;
  const admin = createServiceRoleClient();
  const { data: member } = await admin
    .from("organization_members")
    .select("role")
    .eq("organization_id", orgId)
    .eq("user_id", user.id)
    .maybeSingle();
  if (!member) return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  const out: unknown[] = [];
  for (const orgId of body.linkedOrgIds as string[]) {
    const { data } = await admin.from("projects").select("*").eq("organization_id", orgId);
    out.push(...(data ?? []));
  }
  return NextResponse.json({ projects: out });
}
`),
    ).toEqual([
      {
        line: 11,
        severity: "critical",
        table: "organization_members",
      },
      {
        line: 20,
        severity: "critical",
        table: "projects",
      },
    ]);
  });

  it("CE11: an update filtered by the caller's own id can still move the row into any tenant", () => {
    expect(
      r4In(`import { NextResponse } from "next/server";
import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";

// "Move my seat to another workspace": the caller's own membership row is re-pointed at any organization.
export async function PATCH(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const body = await req.json();
  const admin = createServiceRoleClient();
  const { error } = await admin
    .from("organization_members")
    .update({ organization_id: body.targetOrgId, role: "owner" })
    .eq("organization_id", body.orgId)
    .eq("user_id", user.id);
  if (error) return NextResponse.json({ error: "Failed" }, { status: 500 });
  return NextResponse.json({ ok: true });
}
`),
    ).toEqual([
      {
        line: 10,
        severity: "critical",
        table: "organization_members",
      },
    ]);
  });
});
