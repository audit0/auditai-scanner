/**
 * Identity matrix for fixture 044: the anon key must not reach a SECURITY DEFINER lookup.
 */
import { createClient } from "@supabase/supabase-js";
import { describe, expect, it } from "vitest";

const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY ?? "";
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<"bob", { email: string }>;

describe("find_profile_by_email", () => {
  it("a visitor with the anon key looks up another person: DENY", async () => {
    const anon = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
    const { data, error } = await anon.rpc("find_profile_by_email", { p_email: SEED.bob.email });
    expect(error).not.toBeNull();
    expect(data ?? []).toEqual([]);
  });

  it("the service role still calls it: ALLOW", async () => {
    const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });
    const { error } = await admin.rpc("find_profile_by_email", { p_email: SEED.bob.email });
    expect(error).toBeNull();
  });
});
