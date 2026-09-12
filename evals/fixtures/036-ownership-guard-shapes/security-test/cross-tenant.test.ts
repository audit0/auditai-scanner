/**
 * Security regression test for fixture 036. Identity matrix against the running app, cookie auth.
 * Seed: one project with one task, one document and one report per user.
 */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<
  "alice" | "bob",
  { projectId: string; documentId: string; reportId: string }
>;

async function sessionCookieFor(email: string, password: string): Promise<string> {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  return `sb-access-token=${data.session.access_token}; sb-refresh-token=${data.session.refresh_token}`;
}

function call(cookie: string, path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(`${APP_URL}${path}`, { ...init, headers: { cookie, "content-type": "application/json", ...(init.headers ?? {}) } });
}

async function documentTitle(id: string): Promise<string | null> {
  const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });
  const { data } = await admin.from("documents").select("title").eq("id", id).maybeSingle();
  return data?.title ?? null;
}

describe("ownership guard shapes", () => {
  let alice: string;
  let bob: string;

  beforeAll(async () => {
    alice = await sessionCookieFor("alice@tenant-a.test", "alice-password-123");
    bob = await sessionCookieFor("bob@tenant-b.test", "bob-password-123");
  });

  it("Bob lists Alice's project tasks: DENY", async () => {
    expect((await call(bob, `/api/projects/${SEED.alice.projectId}/tasks`)).status).toBe(404);
  });

  it("Alice lists her own project tasks: ALLOW", async () => {
    expect((await call(alice, `/api/projects/${SEED.alice.projectId}/tasks`)).status).toBe(200);
  });

  it("Bob renames Alice's document: DENY", async () => {
    const before = await documentTitle(SEED.alice.documentId);
    const res = await call(bob, `/api/documents/${SEED.alice.documentId}`, {
      method: "PATCH",
      body: JSON.stringify({ title: "pwned" }),
    });
    expect(res.status).toBe(404);
    expect(await documentTitle(SEED.alice.documentId)).toBe(before);
  });

  it("Alice renames her own document: ALLOW", async () => {
    const res = await call(alice, `/api/documents/${SEED.alice.documentId}`, {
      method: "PATCH",
      body: JSON.stringify({ title: "renamed by alice" }),
    });
    expect(res.status).toBe(200);
    expect(await documentTitle(SEED.alice.documentId)).toBe("renamed by alice");
  });

  it("Bob reads Alice's report, with and without ?all=1: DENY", async () => {
    expect((await call(bob, `/api/reports/${SEED.alice.reportId}`)).status).toBe(404);
    expect((await call(bob, `/api/reports/${SEED.alice.reportId}?all=1`)).status).toBe(404);
  });

  it("Alice reads her own report: ALLOW", async () => {
    expect((await call(alice, `/api/reports/${SEED.alice.reportId}`)).status).toBe(200);
  });
});
