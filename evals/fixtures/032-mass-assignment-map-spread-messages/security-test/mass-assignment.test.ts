/**
 * Security regression test for fixture 032. A posted message may set role and content, nothing
 * else: pinned and cost_cents are server-owned columns. Cookie-based auth, as in fixture 019.
 */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<
  "alice" | "bob",
  { userId: string; chatId: string }
>;

async function sessionCookieFor(email: string, password: string): Promise<string> {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  // The sandbox harness exchanges the access token for the sb-* cookies @supabase/ssr expects.
  return `sb-access-token=${data.session.access_token}; sb-refresh-token=${data.session.refresh_token}`;
}

async function post(cookie: string, chatId: string, body: unknown): Promise<Response> {
  return fetch(`${APP_URL}/api/chats/${chatId}/messages`, {
    method: "POST",
    headers: { cookie, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("POST /api/chats/[id]/messages", () => {
  let alice: string;
  const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });

  beforeAll(async () => {
    alice = await sessionCookieFor("alice@tenant-a.test", "alice-password-123");
  });

  it("DENY: pinned, cost_cents and user_id cannot be set from the request", async () => {
    const content = `over-posting probe ${Date.now()}`;
    const res = await post(alice, SEED.alice.chatId, {
      messages: [{ role: "user", content, pinned: true, cost_cents: 0, user_id: SEED.bob.userId }],
    });
    expect(res.status).toBe(200);
    const { data: row } = await admin
      .from("messages")
      .select("pinned, cost_cents, user_id")
      .eq("content", content)
      .single();
    expect(row).toEqual({ pinned: false, cost_cents: 0, user_id: SEED.alice.userId });
  });

  it("ALLOW: role and content are stored", async () => {
    const content = `plain message ${Date.now()}`;
    expect((await post(alice, SEED.alice.chatId, { messages: [{ role: "user", content }] })).status).toBe(200);
    const { data: row } = await admin
      .from("messages")
      .select("role, content")
      .eq("content", content)
      .single();
    expect(row).toEqual({ role: "user", content });
  });
});
