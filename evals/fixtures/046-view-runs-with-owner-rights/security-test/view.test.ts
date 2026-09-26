/**
 * Identity matrix for fixture 046. The policy on invoices keeps tenants apart; a view without
 * security_invoker runs as its owner and shows every tenant's total to whoever may select it.
 */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY ?? "";
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<"alice" | "bob", { userId: string }>;

async function signIn(email: string, password: string) {
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  return sb;
}

describe("invoice_totals view", () => {
  let alice: Awaited<ReturnType<typeof signIn>>;
  beforeAll(async () => {
    alice = await signIn("alice@tenant-a.test", "alice-password-123");
  });

  it("Alice reads her own total through the view: ALLOW", async () => {
    const { data } = await alice.from("invoice_totals").select("tenant_id").eq("tenant_id", SEED.alice.userId);
    expect(data ?? []).toHaveLength(1);
  });

  it("Alice reads Bob's total through the view: DENY", async () => {
    const { data } = await alice.from("invoice_totals").select("tenant_id").eq("tenant_id", SEED.bob.userId);
    expect(data ?? []).toHaveLength(0);
  });

  it("the anon key reads any total through the view: DENY", async () => {
    const sb = createClient(SUPABASE_URL, ANON_KEY);
    const { data } = await sb.from("invoice_totals").select("tenant_id");
    expect(data ?? []).toHaveLength(0);
  });
});
