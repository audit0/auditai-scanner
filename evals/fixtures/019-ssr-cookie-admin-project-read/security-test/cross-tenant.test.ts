/**
 * Security regression test for fixture 019. Identity matrix executed against the running app,
 * no mocks. Cookie-based auth: the test signs in through GoTrue and forwards the session cookie
 * the way a browser would.
 *
 * Expected on the vulnerable app: "alice -> bob's project" returns 200 (test FAILS).
 * Expected on the secure app: 403 or 404 (test PASSES). Own-project reads must stay 200.
 */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<
  "alice" | "bob",
  { projectId: string }
>;

async function sessionCookieFor(email: string, password: string): Promise<string> {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  // The sandbox harness exchanges the access token for the sb-* cookies @supabase/ssr expects.
  return `sb-access-token=${data.session.access_token}; sb-refresh-token=${data.session.refresh_token}`;
}

async function getProject(cookie: string | null, projectId: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (cookie) headers.cookie = cookie;
  return fetch(`${APP_URL}/api/projects/${projectId}`, { headers });
}

describe("project authorization matrix", () => {
  let alice: string;
  let bob: string;

  beforeAll(async () => {
    alice = await sessionCookieFor("alice@tenant-a.test", "alice-password-123");
    bob = await sessionCookieFor("bob@tenant-b.test", "bob-password-123");
  });

  it("Alice reads her own project: ALLOW", async () => {
    expect((await getProject(alice, SEED.alice.projectId)).status).toBe(200);
  });

  it("Bob reads his own project: ALLOW", async () => {
    expect((await getProject(bob, SEED.bob.projectId)).status).toBe(200);
  });

  it("Alice reads Bob's project (other tenant): DENY", async () => {
    const res = await getProject(alice, SEED.bob.projectId);
    expect([403, 404]).toContain(res.status);
  });

  it("Bob reads Alice's project (other tenant): DENY", async () => {
    const res = await getProject(bob, SEED.alice.projectId);
    expect([403, 404]).toContain(res.status);
  });

  it("Anonymous reads any project: DENY", async () => {
    expect((await getProject(null, SEED.alice.projectId)).status).toBe(401);
  });
});
