/**
 * Identity matrix for fixture 039. Subscribing stays open to everyone; deleting somebody else's
 * subscription must not be.
 */
import { createClient } from "@supabase/supabase-js";
import { describe, expect, it } from "vitest";

const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY ?? "";
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<"alice" | "bob", { subscriberId: string }>;

const anon = () => createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });

describe("subscribers write policies", () => {
  it("a visitor subscribes with the public key: ALLOW", async () => {
    const { error } = await anon().from("subscribers").insert({ email: `visitor-${Date.now()}@example.test` });
    expect(error).toBeNull();
  });

  it("a visitor deletes somebody else's subscription: DENY", async () => {
    const sb = anon();
    await sb.from("subscribers").delete().eq("id", SEED.bob.subscriberId);
    const { count } = await createClient(SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY ?? ANON_KEY)
      .from("subscribers")
      .select("id", { count: "exact", head: true })
      .eq("id", SEED.bob.subscriberId);
    expect(count).toBe(1);
  });

  it("a visitor empties the whole table: DENY", async () => {
    const sb = anon();
    await sb.from("subscribers").delete().neq("email", "");
    const { count } = await createClient(SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY ?? ANON_KEY)
      .from("subscribers")
      .select("id", { count: "exact", head: true });
    expect(count ?? 0).toBeGreaterThan(0);
  });
});
