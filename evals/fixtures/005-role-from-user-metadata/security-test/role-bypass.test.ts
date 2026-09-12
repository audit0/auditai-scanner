/** Fixture 005: a member who edits their own user_metadata must still be refused. */
import { createClient } from "@supabase/supabase-js";
import { describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY ?? "";

describe("admin gate", () => {
  it("DENY: self-promoted member is still denied", async () => {
    const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
    const { data, error } = await sb.auth.signInWithPassword({ email: "alice@tenant-a.test", password: "alice-password-123" });
    if (error || !data.session) throw error ?? new Error("no session");
    await sb.auth.updateUser({ data: { role: "admin" } });
    const { data: refreshed } = await sb.auth.refreshSession();
    const token = refreshed.session?.access_token ?? data.session.access_token;
    const res = await fetch(`${APP_URL}/api/admin/stats`, { headers: { authorization: `Bearer ${token}` } });
    expect(res.status).toBe(403);
  });
});
