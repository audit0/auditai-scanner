/**
 * Security regression test for fixture 023: role must be immutable through PATCH /api/profile,
 * even though the RLS update policy correctly scopes the row to the caller.
 */
import { createClient } from "@supabase/supabase-js";
import { describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY ?? "";
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<
  "alice",
  { userId: string }
>;

describe("PATCH /api/profile", () => {
  it("cannot change role (DENY), display_name still updates (ALLOW)", async () => {
    const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
    const { data, error } = await sb.auth.signInWithPassword({
      email: "alice@tenant-a.test",
      password: "alice-password-123",
    });
    if (error || !data.session) throw error ?? new Error("no session");

    const res = await fetch(`${APP_URL}/api/profile`, {
      method: "PATCH",
      headers: { cookie: `sb-access-token=${data.session.access_token}`, "content-type": "application/json" },
      body: JSON.stringify({ display_name: "Alice", role: "admin" }),
    });
    expect(res.status).toBe(200);

    const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });
    const { data: row } = await admin
      .from("profiles")
      .select("role, display_name")
      .eq("id", SEED.alice.userId)
      .single();
    expect(row?.role).toBe("member");
    expect(row?.display_name).toBe("Alice");
  });

  it("anonymous PATCH: DENY", async () => {
    const res = await fetch(`${APP_URL}/api/profile`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ display_name: "Eve" }),
    });
    expect(res.status).toBe(401);
  });
});
