/**
 * Security regression test for fixture 024. This is the shape Audit AI must generate:
 * an identity matrix executed against the running app, no mocks.
 *
 * Expected on the vulnerable app: "alice (org A) -> bob's (org B) task" returns 200 and the
 * status changes (test FAILS). Expected on the secure app: 403 or 404, status unchanged (test
 * PASSES). Own-org updates must stay 200.
 */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<
  "alice" | "bob",
  { taskId: string }
>;

async function tokenFor(email: string, password: string): Promise<string> {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  return data.session.access_token;
}

async function patchTask(token: string | null, taskId: string, status: string): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  return fetch(`${APP_URL}/api/tasks/${taskId}`, {
    method: "PATCH",
    headers,
    body: JSON.stringify({ status }),
  });
}

describe("task update authorization matrix", () => {
  let alice: string;
  let bob: string;

  beforeAll(async () => {
    alice = await tokenFor("alice@org-a.test", "alice-password-123");
    bob = await tokenFor("bob@org-b.test", "bob-password-123");
  });

  it("Alice updates her own org's task: ALLOW", async () => {
    expect((await patchTask(alice, SEED.alice.taskId, "in_progress")).status).toBe(200);
  });

  it("Bob updates his own org's task: ALLOW", async () => {
    expect((await patchTask(bob, SEED.bob.taskId, "in_progress")).status).toBe(200);
  });

  it("Alice updates Bob's org's task (other org): DENY", async () => {
    const res = await patchTask(alice, SEED.bob.taskId, "done");
    expect([403, 404]).toContain(res.status);
  });

  it("Bob updates Alice's org's task (other org): DENY", async () => {
    const res = await patchTask(bob, SEED.alice.taskId, "done");
    expect([403, 404]).toContain(res.status);
  });

  it("Anonymous updates any task: DENY", async () => {
    expect((await patchTask(null, SEED.alice.taskId, "done")).status).toBe(401);
  });
});
