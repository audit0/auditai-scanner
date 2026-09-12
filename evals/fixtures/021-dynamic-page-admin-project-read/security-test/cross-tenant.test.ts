/**
 * Security regression test for fixture 021. Identity matrix executed against the running app,
 * no mocks. The page is a server component: the assertion is on the HTML response, not JSON.
 *
 * Expected on the vulnerable app: "alice -> bob's project" renders Tenant B's project (test FAILS).
 * Expected on the secure app: Next.js `notFound()` renders (404, test PASSES). Own-project
 * visits must keep rendering (200).
 */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<
  "alice" | "bob",
  { projectId: string; projectName: string }
>;

async function sessionCookieFor(email: string, password: string): Promise<string> {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  return `sb-access-token=${data.session.access_token}; sb-refresh-token=${data.session.refresh_token}`;
}

async function visitProject(cookie: string | null, projectId: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (cookie) headers.cookie = cookie;
  return fetch(`${APP_URL}/projects/${projectId}`, { headers });
}

describe("project page authorization matrix", () => {
  let alice: string;
  let bob: string;

  beforeAll(async () => {
    alice = await sessionCookieFor("alice@tenant-a.test", "alice-password-123");
    bob = await sessionCookieFor("bob@tenant-b.test", "bob-password-123");
  });

  it("Alice visiting her own project sees it: ALLOW", async () => {
    const res = await visitProject(alice, SEED.alice.projectId);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(SEED.alice.projectName);
  });

  it("Alice visiting Bob's project (other tenant): DENY", async () => {
    const res = await visitProject(alice, SEED.bob.projectId);
    expect(res.status).toBe(404);
    expect(await res.text()).not.toContain(SEED.bob.projectName);
  });

  it("Bob visiting Alice's project (other tenant): DENY", async () => {
    const res = await visitProject(bob, SEED.alice.projectId);
    expect(res.status).toBe(404);
  });

  it("Anonymous visitor is redirected to /login: DENY", async () => {
    const res = await visitProject(null, SEED.alice.projectId, );
    expect([302, 307]).toContain(res.status);
  });
});
