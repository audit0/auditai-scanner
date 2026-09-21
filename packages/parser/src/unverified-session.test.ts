import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import type { RouteHandler } from "./model.js";
import { parseProject } from "./parse-project.js";

/**
 * `getSession()` on the server is not the same authentication as `getUser()` or `getClaims()`: it
 * reads the session out of the cookie without revalidating it, so its claims are whatever the
 * browser put there. The parser records which of the three established a session check so a rule
 * can tell them apart; everything else about the check stays as it was.
 */

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "auditai-session-"));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(join(dir, dirname(rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}

function route(files: Record<string, string>, entry?: string): RouteHandler {
  const m = parseProject(project(files));
  const r = entry ? m.routes.find((x) => x.entry === entry) : m.routes[0];
  if (!r) throw new Error(`no route ${entry ?? ""}`);
  return r;
}

const methods = (r: RouteHandler): Array<string | undefined> =>
  r.authChecks.filter((a) => (a.kind ?? "session") === "session").map((a) => a.method);

describe("which call established a session check", () => {
  it("names getSession, and still counts it as an authentication check", () => {
    const r = route({
      "app/api/orders/route.ts": `import { createClient } from "@/lib/server";
export async function GET() {
  const supabase = createClient();
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) return new Response("no", { status: 401 });
  return Response.json(await supabase.from("orders").select("*").eq("user_id", session.user.id));
}`,
    });
    expect(methods(r)).toEqual(["getSession"]);
    expect(r.authChecks.length).toBe(1);
  });

  it("names getUser and getClaims", () => {
    const withUser = route({
      "app/api/a/route.ts": `import { createClient } from "@/lib/server";
export async function GET() {
  const supabase = createClient();
  const { data: { user } } = await supabase.auth.getUser();
  return Response.json(user);
}`,
    });
    expect(methods(withUser)).toEqual(["getUser"]);

    const withClaims = route({
      "app/api/b/route.ts": `import { createClient } from "@/lib/server";
export async function GET() {
  const supabase = createClient();
  const { data } = await supabase.auth.getClaims();
  return Response.json(data);
}`,
    });
    expect(methods(withClaims)).toEqual(["getClaims"]);
  });

  it("reports both when a handler reads the cookie and then verifies it", () => {
    const r = route({
      "app/api/c/route.ts": `import { createClient } from "@/lib/server";
export async function GET() {
  const supabase = createClient();
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) return new Response("no", { status: 401 });
  const { data: { user } } = await supabase.auth.getUser();
  return Response.json(user);
}`,
    });
    expect(methods(r).sort()).toEqual(["getSession", "getUser"]);
  });

  it("carries the method out of an auth helper of this repository", () => {
    const r = route({
      "lib/auth.ts": `import { createClient } from "@/lib/server";
export async function currentSession() {
  const supabase = createClient();
  const { data: { session } } = await supabase.auth.getSession();
  return session;
}`,
      "app/api/d/route.ts": `import { currentSession } from "@/lib/auth";
export async function GET() {
  const session = await currentSession();
  if (!session) return new Response("no", { status: 401 });
  return Response.json(session.user.id);
}`,
    });
    expect(methods(r)).toContain("getSession");
  });
});

/**
 * The Auth admin API acts on accounts rather than on rows, so no policy constrains it. The model
 * records these calls and whether the account they name came from the request or from the caller's
 * own identity. No rule reads this yet: measured on the corpora, a rule built on it alone was right
 * 2 times out of 13, because nearly every admin screen gates itself with a guard helper that returns
 * early and the parser does not yet recognise those (docs/realworld/2026-09-19-recall-round-1.md).
 */
describe("calls to the Auth admin API", () => {
  it("separates an id that came from the request from the caller's own", () => {
    const m = parseProject(
      project({
        "lib/admin.ts": `import { createClient } from "@supabase/supabase-js";
export function admin() { return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!); }`,
        "lib/server.ts": `import { createServerClient } from "@supabase/ssr";
export function createClient() { return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, { cookies: {} as never }); }`,
        "app/api/users/[id]/route.ts": `import { admin } from "@/lib/admin";
export async function DELETE(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  await admin().auth.admin.deleteUser(id);
  return new Response("ok");
}`,
        "app/api/me/route.ts": `import { admin } from "@/lib/admin";
import { createClient } from "@/lib/server";
export async function DELETE() {
  const supabase = createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("no", { status: 401 });
  await admin().auth.admin.deleteUser(user.id);
  return new Response("ok");
}`,
      }),
    );
    const byEntry = new Map(m.routes.map((r) => [r.entry, r.adminApiCalls ?? []]));
    expect(byEntry.get("DELETE /api/users/[id]")).toMatchObject([
      { method: "deleteUser", argText: "id", inputDerived: true, identity: false },
    ]);
    expect(byEntry.get("DELETE /api/me")).toMatchObject([
      { method: "deleteUser", argText: "user.id", inputDerived: false, identity: true },
    ]);
  });
});

/**
 * `export const getUser = cache(async () => {...})` is how App Router code memoises a per-request
 * lookup, and the implementation lives in the argument rather than in a named function. Stepping
 * through the wrapper is what makes the session check, and everything the helper queries, visible at
 * the call site; SiPos and klubb-app both write their whole auth layer this way.
 */
describe("a helper defined inside a wrapper call", () => {
  it("is followed, so the session it establishes reaches the handler", () => {
    const m = parseProject(
      project({
        "lib/server.ts": `import { createServerClient } from "@supabase/ssr";
export function createClient() { return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, { cookies: {} as never }); }`,
        "lib/dal.ts": `import { cache } from "react";
import { createClient } from "@/lib/server";
export const currentUser = cache(async () => {
  const supabase = createClient();
  const { data: { user } } = await supabase.auth.getSession();
  return user ?? null;
});`,
        "app/api/orders/route.ts": `import { currentUser } from "@/lib/dal";
export async function GET() {
  const user = await currentUser();
  if (!user) return new Response("no", { status: 401 });
  return Response.json({ id: user.id });
}`,
      }),
    );
    const r = m.routes.find((x) => x.entry === "GET /api/orders");
    expect(r?.authChecks.some((a) => a.method === "getSession")).toBe(true);
  });

  it("does not follow a wrapper that is only handed a name", () => {
    const m = parseProject(
      project({
        "lib/impl.ts": `export async function impl() { return null; }`,
        "lib/dal.ts": `import { cache } from "react";
import { impl } from "@/lib/impl";
export const currentUser = cache(impl);`,
        "app/api/x/route.ts": `import { currentUser } from "@/lib/dal";
export async function GET() {
  const user = await currentUser();
  return Response.json({ ok: Boolean(user) });
}`,
      }),
    );
    const r = m.routes.find((x) => x.entry === "GET /api/x");
    expect(r?.authChecks ?? []).toEqual([]);
  });
});
