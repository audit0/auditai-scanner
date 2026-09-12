import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import type { RouteHandler } from "./model.js";
import { parseProject } from "./parse-project.js";

/**
 * Precision fixes from the 12 September 2026 real-world run (docs/realworld/2026-09-12.md): taint
 * through method-call receivers, whole-input vs derived values, per-property taint of object
 * arguments, request reads nested in arguments, clients built from headers, Prisma extensions,
 * evidence-based custom authentication and the user_metadata field.
 */

const ADMIN = `import { createClient } from "@supabase/supabase-js";
export function admin() { return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!); }
`;

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "auditai-precision-"));
  for (const [rel, text] of Object.entries({ "lib/admin.ts": ADMIN, ...files })) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
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

const idFilterDerived = (r: RouteHandler, table: string): boolean | undefined =>
  r.queries.find((q) => q.table === table)?.filters.find((f) => f.column === "id")?.inputDerived;

describe("taint through a method-call receiver (fixture 020)", () => {
  it("taints formData.get() assigned to a local const in a server action", () => {
    const r = route({
      "app/documents/actions.ts": `"use server";
import { admin } from "@/lib/admin";
export async function deleteDocument(formData: FormData) {
  const id = formData.get("id") as string;
  await admin().from("documents").delete().eq("id", id);
}`,
    });
    expect(idFilterDerived(r, "documents")).toBe(true);
  });

  it("taints req.formData().get(), URLSearchParams.get() and Map.get()", () => {
    const r = route({
      "app/api/docs/route.ts": `import { admin } from "@/lib/admin";
export async function POST(req: Request) {
  const form = await req.formData();
  const a = form.get("a") as string;
  const sp = new URLSearchParams(await req.text());
  const b = sp.get("b");
  const byKey = new Map(Object.entries(await req.json()));
  const c = byKey.get("c");
  await admin().from("a").delete().eq("id", a);
  await admin().from("b").delete().eq("id", b);
  await admin().from("c").delete().eq("id", c);
}`,
    });
    expect(["a", "b", "c"].map((t) => idFilterDerived(r, t))).toEqual([true, true, true]);
  });

  it("taints request reads inside helpers and nested in arguments", () => {
    const r = route({
      "lib/body.ts": `import { admin } from "@/lib/admin";
export async function removeFrom(req: Request) {
  const { id } = await req.json();
  await admin().from("inside").delete().eq("id", id);
}`,
      "app/api/x/route.ts": `import { admin } from "@/lib/admin";
import { removeFrom } from "@/lib/body";
export async function POST(req: Request) {
  const payload = schema.parse(await readJsonWithLimit(req));
  const parsed = schema.parse(await req.json());
  await admin().from("nested").delete().eq("id", payload.id);
  await admin().from("zod").delete().eq("id", parsed.id);
  await removeFrom(req);
}`,
    });
    expect(["nested", "zod", "inside"].map((t) => idFilterDerived(r, t))).toEqual([
      true,
      true,
      true,
    ]);
  });

  it("does not treat the session on the request (req.auth) as input", () => {
    const r = route({
      "app/api/me/route.ts": `import { admin } from "@/lib/admin";
export async function GET(req: Request & { auth: { user: { id: string } } }) {
  const userId = req.auth.user.id;
  await admin().from("profiles").select("*").eq("id", userId);
}`,
    });
    expect(idFilterDerived(r, "profiles")).toBe(false);
  });
});

describe("what a helper returns (return taint, 13 September 2026 labels)", () => {
  const filter = (r: RouteHandler, table: string, column: string): boolean | undefined =>
    r.queries
      .filter((q) => q.table === table)
      .flatMap((q) => q.filters)
      .find((f) => f.column === column)?.inputDerived;

  it("keeps a row looked up by the caller's credential clean (wacrm requireApiKey, touchLastUsed)", () => {
    const r = route({
      "lib/keys.ts": `import { admin } from "@/lib/admin";
export function hashApiKey(key: string) { return createHash("sha256").update(key).digest("hex"); }
export async function findActiveKeyByHash(hash: string) {
  const { data, error } = await admin().from("api_keys").select("id, account_id").eq("key_hash", hash).maybeSingle();
  if (error) return null;
  if (!data) return null;
  return data as { id: string; account_id: string };
}
export function touchLastUsed(id: string) {
  void admin().from("api_keys").update({ last_used_at: new Date().toISOString() }).eq("id", id);
}
function extractKey(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (!header) return null;
  const value = header.startsWith("Bearer ") ? header.slice(7).trim() : header.trim();
  return value.length > 0 ? value : null;
}
export async function requireApiKey(request: Request, scope?: string) {
  const presented = extractKey(request);
  if (!presented) throw new Error("unauthorized");
  const row = await findActiveKeyByHash(hashApiKey(presented));
  if (!row) throw new Error("unauthorized");
  touchLastUsed(row.id);
  return { authType: "api_key" as const, accountId: row.account_id, keyId: row.id, presented };
}`,
      "app/api/v1/me/route.ts": `import { admin } from "@/lib/admin";
import { requireApiKey } from "@/lib/keys";
export async function GET(request: Request) {
  const ctx = await requireApiKey(request);
  const { data } = await admin().from("accounts").select("name").eq("id", ctx.accountId).maybeSingle();
  await admin().from("audit").insert({ presented: ctx.presented });
  return Response.json({ name: data?.name, key: ctx.keyId });
}`,
    });
    expect(r.authChecks.map((a) => a.kind)).toEqual(["credential"]);
    expect(filter(r, "api_keys", "id")).toBe(false);
    expect(filter(r, "accounts", "id")).toBe(false);
    // The one property built from the request stays tainted.
    expect(r.queries.find((q) => q.table === "audit")?.payload?.inputDerived).toBe(true);
  });

  it("keeps the id of a row this request created clean (PriceAI createOfferFeedback, after())", () => {
    const r = route({
      "lib/feedback.ts": `import { admin } from "@/lib/admin";
export async function createFeedback(input: { offerId: string | null; reason: string }) {
  const { data } = await admin().from("feedback").insert({ offer_id: input.offerId, reason: input.reason }).select("id").single();
  return { id: data.id, status: "pending" as const };
}
export async function verify(feedbackId: string) {
  const { data } = await admin().from("feedback").select("*").eq("id", feedbackId).maybeSingle();
  return data;
}`,
      "app/api/feedback/route.ts": `import { admin } from "@/lib/admin";
import { createFeedback, verify } from "@/lib/feedback";
export async function POST(request: Request) {
  const payload = await request.json();
  const result = await createFeedback({ offerId: payload.offerId || null, reason: payload.reason });
  await admin().from("feedback").delete().eq("id", result.id);
  after(async () => { await verify(result.id); });
  return Response.json({ id: result.id });
}`,
    });
    const feedback = r.queries.filter((q) => q.table === "feedback");
    expect(feedback.map((q) => [q.operation, q.filters[0]?.inputDerived ?? null]).sort()).toEqual([
      ["delete", false],
      ["insert", null],
      ["select", false],
    ]);
    expect(feedback.find((q) => q.operation === "insert")?.payload?.inputDerived).toBe(true);
  });

  it("taints a helper's result when it returns its input, a property of it, or an object carrying it", () => {
    const r = route({
      "lib/pick.ts": `import { admin } from "@/lib/admin";
export function pickId(body: { id: string }) { return body.id; }
export async function wrap(body: { id: string }) {
  const row = await admin().from("x").select("*").eq("id", body.id).single();
  return { id: body.id, row: row.data };
}
export async function either(body: { id: string }, flag: boolean) {
  const found = await admin().from("y").select("id").eq("slug", body.id).maybeSingle();
  return flag ? found.data : body;
}`,
      "app/api/pick/route.ts": `import { admin } from "@/lib/admin";
import { either, pickId, wrap } from "@/lib/pick";
export async function POST(req: Request) {
  const body = await req.json();
  const a = pickId(body);
  const b = await wrap(body);
  const c = await either(body, true);
  await admin().from("a").delete().eq("id", a);
  await admin().from("b").delete().eq("id", b.id);
  await admin().from("b2").delete().eq("id", b.row.id);
  await admin().from("c").delete().eq("id", c.id);
}`,
    });
    expect(["a", "b", "b2", "c"].map((t) => filter(r, t, "id"))).toEqual([true, true, false, true]);
  });

  it("assumes an unresolvable helper returns its input, whole (mass assignment stays visible)", () => {
    const r = route({
      "app/api/profile/route.ts": `import { admin } from "@/lib/admin";
export async function POST(req: Request) {
  const body = schema.parse(await req.json());
  await admin().from("profiles").update(body).eq("id", "x");
}`,
    });
    expect(r.queries[0]?.payload).toMatchObject({ inputDerived: true, wholeInput: true });
  });
});

describe("per-property taint of an object argument", () => {
  it("keeps a session-derived property clean when a sibling comes from the body (wacrm engine)", () => {
    const r = route({
      "lib/engine.ts": `import { admin } from "@/lib/admin";
export async function run(input: { accountId: string; contactId: string | null }) {
  await admin().from("automations").select("*").eq("account_id", input.accountId);
  await admin().from("contacts").select("*").eq("id", input.contactId);
}
export async function runDestructured({ accountId, contactId }: { accountId: string; contactId: string }) {
  await admin().from("steps").select("*").eq("account_id", accountId).eq("contact_id", contactId);
}`,
      "app/api/engine/route.ts": `import { run, runDestructured } from "@/lib/engine";
export async function POST(request: Request) {
  const ctx = await requireRole("agent");
  const body = await request.json().catch(() => null);
  await run({ accountId: ctx.accountId, contactId: body.contact_id ?? null });
  await runDestructured({ accountId: ctx.accountId, contactId: body.contact_id });
}`,
    });
    const filters = (t: string) =>
      r.queries.find((q) => q.table === t)?.filters.map((f) => [f.column, f.inputDerived]);
    expect(filters("automations")).toEqual([["account_id", false]]);
    expect(filters("contacts")).toEqual([["id", true]]);
    expect(filters("steps")).toEqual([
      ["account_id", false],
      ["contact_id", true],
    ]);
  });
});

describe("whole input vs values derived from it (mass assignment)", () => {
  it("does not mark a .map() that rebuilds explicit fields as whole input", () => {
    const r = route({
      "app/api/chat/route.ts": `import { admin } from "@/lib/admin";
export async function POST(request: Request) {
  const { id, messages } = await request.json();
  const rows = messages.map((m) => ({ id: crypto.randomUUID(), chat_id: id, role: m.role, content: m.content }));
  await admin().from("messages").insert(rows);
  const patch = { chat_id: id, updated_at: new Date().toISOString() };
  await admin().from("chats").update(patch).eq("owner_id", "x");
  await admin().from("raw").insert(messages.map((m) => ({ ...m, chat_id: id })));
}`,
    });
    const payload = (t: string) => r.queries.find((q) => q.table === t)?.payload;
    expect(payload("messages")).toMatchObject({ inputDerived: true, wholeInput: false });
    expect(payload("chats")).toMatchObject({ inputDerived: true, wholeInput: false });
    expect(payload("raw")).toMatchObject({ wholeInput: true });
  });

  it("keeps the raw body passed to a helper whole (firestarta createUser)", () => {
    const r = route({
      "lib/users.ts": `import { admin } from "@/lib/admin";
export async function createUser(user: unknown) { return admin().from("users").insert(user); }
export async function updateUser(email: string, data: unknown) { return admin().from("users").update(data).eq("email", email); }`,
      "app/api/users/route.ts": `import { createUser, updateUser } from "@/lib/users";
export async function POST(req: Request) {
  const data = await req.json();
  await createUser(data);
  const { ...rest } = await req.json();
  await updateUser("a@b.c", rest);
}`,
    });
    expect(r.queries.map((q) => [q.operation, q.payload?.wholeInput])).toEqual([
      ["insert", true],
      ["update", true],
    ]);
  });
});

describe("clients", () => {
  it("classifies a client built with the request's Authorization header as a client, not header input", () => {
    const r = route({
      "app/api/notes/route.ts": `import { createClient } from "@supabase/supabase-js";
export async function GET(req: Request) {
  const sb = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!, {
    global: { headers: { Authorization: req.headers.get("Authorization")! } },
  });
  const { data } = await sb.from("notes").select("*");
  return Response.json(data);
}`,
    });
    expect(r.queries[0]).toMatchObject({
      table: "notes",
      client: "user_scoped",
      clientName: "createClient",
    });
    expect(r.inputs.map((i) => i.kind)).not.toContain("header");
  });

  it("keeps a Prisma client extended with $extends a direct connection (expense.fyi)", () => {
    const r = route({
      "lib/prisma.ts": `import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
const prismaClient = prisma.$extends(fieldEncryptionExtension());
export default prismaClient;`,
      "app/api/expenses/route.ts": `import prisma from "@/lib/prisma";
export async function DELETE(request: Request) {
  const { id } = await request.json();
  return await checkAuth(async () => {
    await prisma.expenses.delete({ where: { id: id[0] } });
  });
}`,
    });
    expect(r.queries[0]).toMatchObject({ operation: "delete", client: "direct_db" });
    expect(r.queries[0]?.filters[0]).toMatchObject({ column: "id", inputDerived: true });
  });
});

describe("custom authentication (evidence-based)", () => {
  const kinds = (r: RouteHandler) => r.authChecks.map((a) => a.kind);

  it("recognises a cron secret compared with the Authorization header", () => {
    const r = route({
      "app/api/cron/route.ts": `import { admin } from "@/lib/admin";
export async function GET(req: Request) {
  if (req.headers.get("authorization") !== \`Bearer \${process.env.CRON_SECRET}\`) {
    return new Response("Unauthorized", { status: 401 });
  }
  await admin().from("jobs").delete().lt("run_at", new Date().toISOString());
}`,
    });
    expect(kinds(r)).toEqual(["secret"]);
  });

  it("recognises an admin-password helper two calls away (PriceAI requireAdminRequest)", () => {
    const r = route({
      "lib/admin-auth.ts": `import { timingSafeEqual } from "node:crypto";
export async function requireAdminRequest(request: Request): Promise<void> {
  if (await isAdminRequest(request)) return;
  throw new Error("unauthorized");
}
async function isAdminRequest(request: Request): Promise<boolean> {
  const header = request.headers.get("x-admin-password")?.trim();
  return Boolean(header && (await verifyAdminPassword(header)));
}
async function verifyAdminPassword(value: string): Promise<boolean> {
  const bootstrap = getRuntimeEnv("ADMIN_PASSWORD");
  return Boolean(bootstrap && timingSafeEqual(value, bootstrap));
}`,
      "app/api/admin/sources/route.ts": `import { admin } from "@/lib/admin";
import { requireAdminRequest } from "@/lib/admin-auth";
export async function DELETE(request: Request) {
  await requireAdminRequest(request);
  const { id } = await request.json();
  await admin().from("sources").delete().eq("id", id);
}`,
    });
    expect(kinds(r)).toEqual(["secret"]);
  });

  it("recognises an Auth.js session helper followed by a redirect (lipi getCurrentUser)", () => {
    const r = route({
      "lib/auth.ts": `import NextAuth from "next-auth";
export const { handlers, auth, signIn, signOut } = NextAuth({ providers: [] });
export const getCurrentUser = async () => {
  const session = await auth();
  return session?.user;
};`,
      "app/dashboard/page.tsx": `import { redirect } from "next/navigation";
import { getCurrentUser } from "@/lib/auth";
import { admin } from "@/lib/admin";
export default async function DashboardPage() {
  const user = await getCurrentUser();
  if (!user) redirect("/login");
  const { data } = await admin().from("workspaces").select("*").eq("owner_id", user.id);
  return <pre>{JSON.stringify(data)}</pre>;
}`,
    });
    expect(kinds(r)).toEqual(["session"]);
  });

  it("recognises getServerSession from next-auth", () => {
    const r = route({
      "app/api/me/route.ts": `import { getServerSession } from "next-auth";
import { admin } from "@/lib/admin";
export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session) return new Response("no", { status: 401 });
  await admin().from("profiles").select("*").eq("email", session.user.email);
}`,
    });
    expect(kinds(r)).toEqual(["session"]);
  });

  it("recognises an API key looked up by its hash (wacrm requireApiKey)", () => {
    const r = route({
      "lib/keys.ts": `import { admin } from "@/lib/admin";
export async function requireApiKey(request: Request) {
  const presented = request.headers.get("authorization")?.slice(7) ?? "";
  const row = await findActiveKeyByHash(hashApiKey(presented));
  if (!row) throw new Error("unauthorized");
  return { accountId: row.account_id };
}
async function findActiveKeyByHash(hash: string) {
  const { data } = await admin().from("api_keys").select("id, account_id").eq("key_hash", hash).maybeSingle();
  return data;
}`,
      "app/api/v1/me/route.ts": `import { requireApiKey } from "@/lib/keys";
export async function GET(request: Request) {
  const ctx = await requireApiKey(request);
  return Response.json(ctx);
}`,
    });
    expect(kinds(r)).toEqual(["credential"]);
  });

  it("does not count a helper merely named like authentication", () => {
    const r = route({
      "lib/guard.ts": `export async function requireAuth(request: Request) { return request.headers.get("x-user"); }`,
      "app/api/admin/users/route.ts": `import { admin } from "@/lib/admin";
import { requireAuth } from "@/lib/guard";
export async function GET(request: Request) {
  await requireAuth(request);
  return Response.json(await admin().from("profiles").select("*"));
}`,
    });
    expect(r.authChecks).toEqual([]);
  });
});

describe("role gates of the session (ADR-001, pasal isAdminEmail)", () => {
  const SESSION = `import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
export async function createClient() {
  const store = await cookies();
  return createServerClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!, {
    cookies: { getAll: () => store.getAll(), setAll: () => {} },
  });
}`;
  const ADMIN_AUTH = `import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase-server";
export const ADMIN_EMAILS = (process.env.ADMIN_EMAILS ?? "").split(",");
export function isAdminEmail(email: string | undefined | null): boolean {
  return !!email && ADMIN_EMAILS.includes(email.toLowerCase());
}
export async function requireAdmin() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/admin/login");
  if (!user.email || !ADMIN_EMAILS.includes(user.email)) redirect("/admin/login?error=unauthorized");
  return { email: user.email, userId: user.id };
}`;
  const sources = (r: RouteHandler) => (r.roleChecks ?? []).map((c) => c.source);

  it("records isAdminEmail(user.email) on the session user, with an exit", () => {
    const r = route({
      "lib/supabase-server.ts": SESSION,
      "lib/admin-auth.ts": ADMIN_AUTH,
      "app/api/admin/works/[id]/route.ts": `import { admin } from "@/lib/admin";
import { createClient } from "@/lib/supabase-server";
import { isAdminEmail } from "@/lib/admin-auth";
export async function PATCH(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user || !isAdminEmail(user.email)) return new Response("no", { status: 401 });
  const { id } = await params;
  await admin().from("works").update({ status: "x" }).eq("id", id);
}`,
    });
    expect(sources(r)).toEqual(["user.email"]);
    expect(r.roleChecks?.[0]?.text).toContain("isAdminEmail(user.email)");
  });

  it("records app_metadata role comparisons and a redirecting helper, never user_metadata or a row compare", () => {
    const r = route({
      "lib/supabase-server.ts": SESSION,
      "lib/admin-auth.ts": ADMIN_AUTH,
      "app/api/admin/x/route.ts": `import { admin } from "@/lib/admin";
import { createClient } from "@/lib/supabase-server";
import { requireAdmin } from "@/lib/admin-auth";
export async function POST(request: Request) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("no", { status: 401 });
  if (user.app_metadata?.role !== "admin") return new Response("no", { status: 403 });
  if (user.user_metadata?.role !== "admin") return new Response("no", { status: 403 });
  const { data: row } = await admin().from("works").select("user_id").eq("id", "x").single();
  if (row.user_id !== user.id) return new Response("no", { status: 403 });
  await requireAdmin();
  return Response.json({ ok: true });
}`,
    });
    expect(sources(r)).toEqual(["user.app_metadata.role", "user.email"]);
  });

  it("ignores a gate whose return does not stop the entry point, and helpers without a session value", () => {
    const r = route({
      "lib/supabase-server.ts": SESSION,
      "lib/guard.ts": `export function isAdmin(): boolean { return process.env.ALLOW_ALL === "1"; }
export async function softCheck(user: { email?: string }) { if (!user.email) return false; return true; }`,
      "app/api/admin/y/route.ts": `import { admin } from "@/lib/admin";
import { createClient } from "@/lib/supabase-server";
import { isAdmin, softCheck } from "@/lib/guard";
export async function POST(request: Request) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user || !isAdmin()) return new Response("no", { status: 401 });
  await softCheck(user);
  return Response.json({ ok: true });
}`,
    });
    expect(sources(r)).toEqual([]);
  });
});

describe("user_metadata accesses", () => {
  it("records the metadata field separately from the path", () => {
    const r = route({
      "app/api/admin/tenants/route.ts": `import { admin } from "@/lib/admin";
export async function POST(req: Request) {
  const adminCtx = await getAdminContext(req);
  const actor = adminCtx.user.user_metadata?.full_name;
  if (adminCtx.user.user_metadata?.role !== "admin") return new Response("no", { status: 403 });
  await admin().from("audit").insert({ actor });
}`,
    });
    expect(r.metadataAccesses.map((m) => m.field)).toEqual(["full_name", "role"]);
  });
});

describe("model warnings", () => {
  it("carries discovery warnings (a rejected ignore glob) into ProjectModel.warnings", () => {
    const dir = project({ "app/api/x/route.ts": "export async function GET() {}" });
    const m = parseProject(dir, { ignore: ["**"] });
    expect(m.warnings.some((w) => w.includes("rejected"))).toBe(true);
    expect(m.routes.map((r) => r.entry)).toEqual(["GET /api/x"]);
  });
});
