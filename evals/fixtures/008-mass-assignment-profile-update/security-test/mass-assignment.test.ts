/** Fixture 008: role and tenant_id must be immutable through PATCH /api/profile. */
import { createClient } from "@supabase/supabase-js";
import { describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY ?? "";
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<"alice" | "bob", { userId: string; tenantId: string }>;

describe("PATCH /api/profile", () => {
  it("cannot change role or tenant", async () => {
    const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
    const { data, error } = await sb.auth.signInWithPassword({ email: "alice@tenant-a.test", password: "alice-password-123" });
    if (error || !data.session) throw error ?? new Error("no session");
    await fetch(`${APP_URL}/api/profile`, {
      method: "PATCH",
      headers: { authorization: `Bearer ${data.session.access_token}`, "content-type": "application/json" },
      body: JSON.stringify({ display_name: "Alice", role: "admin", tenant_id: SEED.bob.tenantId }),
    });
    const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });
    const { data: row } = await admin.from("profiles").select("role, tenant_id").eq("id", SEED.alice.userId).single();
    expect(row).toEqual({ role: "member", tenant_id: SEED.alice.tenantId });
  });
});
