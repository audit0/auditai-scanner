/**
 * Security regression test for fixture 031. Identity matrix executed against the running app,
 * no mocks. Cookie-based auth: the test signs in through GoTrue and forwards the session cookie
 * the way a browser would.
 *
 * Expected on the vulnerable app: "bob -> alice's flow" returns 200 and the row is gone (test FAILS).
 * Expected on the secure app: 404 and the row stays (test PASSES). Own-flow deletes must stay 200.
 */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<
  "alice" | "bob",
  { flowId: string }
>;

async function sessionCookieFor(email: string, password: string): Promise<string> {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  // The sandbox harness exchanges the access token for the sb-* cookies @supabase/ssr expects.
  return `sb-access-token=${data.session.access_token}; sb-refresh-token=${data.session.refresh_token}`;
}

async function deleteFlow(cookie: string | null, flowId: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (cookie) headers.cookie = cookie;
  return fetch(`${APP_URL}/api/flows/${flowId}`, { method: "DELETE", headers });
}

async function flowExists(id: string): Promise<boolean> {
  const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });
  const { data } = await admin.from("flows").select("id").eq("id", id).maybeSingle();
  return data?.id === id;
}

describe("flow delete authorization matrix", () => {
  let alice: string;
  let bob: string;

  beforeAll(async () => {
    alice = await sessionCookieFor("alice@tenant-a.test", "alice-password-123");
    bob = await sessionCookieFor("bob@tenant-b.test", "bob-password-123");
  });

  it("Anonymous deletes a flow: DENY", async () => {
    expect((await deleteFlow(null, SEED.alice.flowId)).status).toBe(401);
    expect(await flowExists(SEED.alice.flowId)).toBe(true);
  });

  it("Bob deletes Alice's flow (other tenant): DENY", async () => {
    const res = await deleteFlow(bob, SEED.alice.flowId);
    expect([403, 404]).toContain(res.status);
    expect(await flowExists(SEED.alice.flowId)).toBe(true);
  });

  it("Alice deletes her own flow: ALLOW", async () => {
    expect((await deleteFlow(alice, SEED.alice.flowId)).status).toBe(200);
    expect(await flowExists(SEED.alice.flowId)).toBe(false);
  });
});
