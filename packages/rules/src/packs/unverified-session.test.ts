import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Finding } from "@auditai/core";
import { buildGraph } from "@auditai/graph";
import { parseProject } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { runRules } from "../rule.js";
import { middlewareCovers, supabaseAuthorizationPack } from "./supabase-authorization.js";

/**
 * R9, `server-trusts-unverified-session`. Supabase's guidance is "never trust
 * supabase.auth.getSession() inside server code": it reads the session out of the cookie without
 * revalidating it. Each vulnerable shape below sits next to the one that must stay silent, because
 * the difference between them is the whole rule: who verified the token, and whether its claims
 * decide anything.
 */

const SCHEMA = `create table public.orders (id uuid primary key, user_id uuid not null, total numeric);
alter table public.orders enable row level security;
create policy "own orders" on public.orders for select using (auth.uid() = user_id);
`;

const SERVER = `import { createServerClient } from "@supabase/ssr";
export function createClient() { return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, { cookies: {} as never }); }
`;

const ADMIN = `import { createClient } from "@supabase/supabase-js";
export function admin() { return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!); }
`;

function scan(files: Record<string, string>): Finding[] {
  const dir = mkdtempSync(join(tmpdir(), "auditai-r9-"));
  const all = {
    "lib/server.ts": SERVER,
    "lib/admin.ts": ADMIN,
    "supabase/migrations/0001_init.sql": SCHEMA,
    ...files,
  };
  for (const [rel, text] of Object.entries(all)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  const model = parseProject(dir, { sqlDirs: ["supabase/migrations"] });
  return runRules(supabaseAuthorizationPack, model, buildGraph(model), {
    now: "2026-09-19T00:00:00Z",
  });
}

const R9 = "supabase.server-trusts-unverified-session";
const of = (fs: Finding[], rule: string): Finding[] => fs.filter((f) => f.ruleId === rule);

describe("a query the forged identity actually decides", () => {
  it("is a finding when the scoped query runs with the service-role key", () => {
    const f = of(
      scan({
        "app/api/orders/route.ts": `import { createClient } from "@/lib/server";
import { admin } from "@/lib/admin";
export async function GET() {
  const supabase = createClient();
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) return new Response("no", { status: 401 });
  const { data } = await admin().from("orders").select("*").eq("user_id", session.user.id);
  return Response.json(data);
}`,
      }),
      R9,
    );
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("high");
    expect(f[0]?.entrypoints).toEqual(["GET /api/orders"]);
    expect(f[0]?.evidence[0]?.summary).toContain("getSession()");
  });

  // The line the rule draws: with the caller's own cookie client the request still goes through
  // PostgREST, which refuses a token whose signature does not match, and then through Row Level
  // Security. An unverified read of the cookie buys the attacker nothing there.
  it("stays silent when the same query runs under Row Level Security", () => {
    const f = of(
      scan({
        "app/api/orders/route.ts": `import { createClient } from "@/lib/server";
export async function GET() {
  const supabase = createClient();
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) return new Response("no", { status: 401 });
  const { data } = await supabase.from("orders").select("*").eq("user_id", session.user.id);
  return Response.json(data);
}`,
      }),
      R9,
    );
    expect(f).toHaveLength(0);
  });

  it("is silent once the same handler verifies with getUser", () => {
    const f = of(
      scan({
        "app/api/orders/route.ts": `import { createClient } from "@/lib/server";
import { admin } from "@/lib/admin";
export async function GET() {
  const supabase = createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("no", { status: 401 });
  const { data } = await admin().from("orders").select("*").eq("user_id", user.id);
  return Response.json(data);
}`,
      }),
      R9,
    );
    expect(f).toHaveLength(0);
  });

  it("is silent when getClaims verifies the token the handler read from the cookie", () => {
    const f = of(
      scan({
        "app/api/orders/route.ts": `import { createClient } from "@/lib/server";
import { admin } from "@/lib/admin";
export async function GET() {
  const supabase = createClient();
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) return new Response("no", { status: 401 });
  const { data: claims } = await supabase.auth.getClaims();
  const { data } = await admin().from("orders").select("*").eq("user_id", claims.sub);
  return Response.json(data);
}`,
      }),
      R9,
    );
    expect(f).toHaveLength(0);
  });
});

describe("what the unverified claims decide", () => {
  it("stays silent when the handler only asks whether somebody is signed in", () => {
    const f = of(
      scan({
        "app/api/ping/route.ts": `import { createClient } from "@/lib/server";
export async function GET() {
  const supabase = createClient();
  const { data: { session } } = await supabase.auth.getSession();
  return Response.json({ signedIn: Boolean(session) });
}`,
      }),
      R9,
    );
    expect(f).toHaveLength(0);
  });

  it("stays silent when the session is read only for its access token", () => {
    const f = of(
      scan({
        "app/api/proxy/route.ts": `import { createClient } from "@/lib/server";
export async function GET() {
  const supabase = createClient();
  const { data: { session } } = await supabase.auth.getSession();
  const upstream = await fetch("https://api.example.com/v1/me", {
    headers: { authorization: "Bearer " + session?.access_token },
  });
  return Response.json(await upstream.json());
}`,
      }),
      R9,
    );
    expect(f).toHaveLength(0);
  });
});

describe("a role gate standing on unverified claims", () => {
  // app_metadata is not editable through the user's profile, which is why role gates lean on it.
  // A forged cookie edits the token itself, so the distinction disappears unless somebody verifies it.
  it("is a finding when the admin gate reads a claim of the unverified session", () => {
    const f = of(
      scan({
        "app/api/admin/refunds/route.ts": `import { createClient } from "@/lib/server";
import { admin } from "@/lib/admin";
export async function POST(req: Request) {
  const supabase = createClient();
  const { data: { session } } = await supabase.auth.getSession();
  if (session?.user.app_metadata?.role !== "admin") return new Response("no", { status: 403 });
  const body = await req.json();
  await admin().from("orders").update({ total_cents: 0 }).eq("id", body.id);
  return new Response("ok");
}`,
      }),
      R9,
    );
    expect(f).toHaveLength(1);
    expect(f[0]?.evidence[0]?.summary).toContain("role gate");
  });

  it("is silent when the same gate stands on a verified session", () => {
    const f = of(
      scan({
        "app/api/admin/refunds/route.ts": `import { createClient } from "@/lib/server";
import { admin } from "@/lib/admin";
export async function POST(req: Request) {
  const supabase = createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (user?.app_metadata?.role !== "admin") return new Response("no", { status: 403 });
  const body = await req.json();
  await admin().from("orders").update({ total_cents: 0 }).eq("id", body.id);
  return new Response("ok");
}`,
      }),
      R9,
    );
    expect(f).toHaveLength(0);
  });
});

describe("a session that came out of a helper", () => {
  it("is a finding when the helper itself calls getSession", () => {
    const f = of(
      scan({
        "lib/auth.ts": `import { createClient } from "@/lib/server";
export async function currentSession() {
  const supabase = createClient();
  const { data: { session } } = await supabase.auth.getSession();
  return session;
}`,
        "app/api/orders/route.ts": `import { admin } from "@/lib/admin";
import { currentSession } from "@/lib/auth";
export async function GET() {
  const session = await currentSession();
  if (!session) return new Response("no", { status: 401 });
  const { data } = await admin().from("orders").select("*").eq("user_id", session.user.id);
  return Response.json(data);
}`,
      }),
      R9,
    );
    expect(f).toHaveLength(1);
  });

  it("is silent when the helper verifies with getUser", () => {
    const f = of(
      scan({
        "lib/auth.ts": `import { createClient } from "@/lib/server";
export async function currentUser() {
  const supabase = createClient();
  const { data: { user } } = await supabase.auth.getUser();
  return user;
}`,
        "app/api/orders/route.ts": `import { admin } from "@/lib/admin";
import { currentUser } from "@/lib/auth";
export async function GET() {
  const user = await currentUser();
  if (!user) return new Response("no", { status: 401 });
  const { data } = await admin().from("orders").select("*").eq("user_id", user.id);
  return Response.json(data);
}`,
      }),
      R9,
    );
    expect(f).toHaveLength(0);
  });
});

/**
 * Which handlers a verifying middleware actually protects. Both matchers below are copied from
 * repositories in the corpora, because they are what made the difference: klubb-app matches
 * everything but a few paths and documents that getSession() is safe behind it, while GoalSquad
 * verifies in middleware and lists only page prefixes, so its /api handlers stand alone.
 */
describe("a middleware matcher", () => {
  const GOALSQUAD = [
    "/dashboard/:path*",
    "/admin/:path*",
    "/merchants/:path*",
    "/orders/:path*",
    "/account/:path*",
  ];
  const KLUBB = [
    "/((?!_next/static|_next/image|favicon.ico|manifest.webmanifest|sw.js|icon-|api/cron/|api/github/|api/ping|.*\\.jpg|.*\\.png|.*\\.svg|.*\\.webp).*)",
  ];

  it("covers everything when the middleware exports none", () => {
    expect(middlewareCovers([], "/api/anything")).toBe(true);
  });

  it("reads page prefixes as prefixes, and leaves /api outside them", () => {
    expect(middlewareCovers(GOALSQUAD, "/admin/campaigns")).toBe(true);
    expect(middlewareCovers(GOALSQUAD, "/dashboard")).toBe(true);
    expect(middlewareCovers(GOALSQUAD, "/api/admin/reports/generate")).toBe(false);
  });

  it("reads the catch-all regular expression, including what it excludes", () => {
    expect(middlewareCovers(KLUBB, "/")).toBe(true);
    expect(middlewareCovers(KLUBB, "/api/medlemmer")).toBe(true);
    expect(middlewareCovers(KLUBB, "/api/ping")).toBe(false);
  });

  it("treats a matcher it cannot compile as protecting nothing", () => {
    expect(middlewareCovers(["/((("], "/api/x")).toBe(false);
  });
});
