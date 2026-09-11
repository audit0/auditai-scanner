/** Fixture 007: the admin listing must refuse anonymous and non-admin callers. */
import { createClient } from "@supabase/supabase-js";
import { describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY ?? "";

async function tokenFor(email: string, password: string): Promise<string> {
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  return data.session.access_token;
}

describe("GET /api/admin/users", () => {
  it("anonymous: DENY", async () => expect((await fetch(`${APP_URL}/api/admin/users`)).status).toBe(401));
  it("member: DENY", async () => {
    const alice = await tokenFor("alice@tenant-a.test", "alice-password-123");
    expect((await fetch(`${APP_URL}/api/admin/users`, { headers: { authorization: `Bearer ${alice}` } })).status).toBe(403);
  });
  it("admin: ALLOW", async () => {
    const admin = await tokenFor("admin@tenant-a.test", "admin-password-123");
    expect((await fetch(`${APP_URL}/api/admin/users`, { headers: { authorization: `Bearer ${admin}` } })).status).toBe(200);
  });
});
