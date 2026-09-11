/**
 * Security regression test for fixture 011. This is the shape Audit AI must generate:
 * an identity matrix executed against the running app, no mocks.
 *
 * Expected on the vulnerable app: "alice -> bob's invoice" returns 200 (test FAILS).
 * Expected on the secure app: 403 or 404 (test PASSES). Own-invoice reads must stay 200.
 */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<
  "alice" | "bob",
  { invoiceId: string }
>;

async function tokenFor(email: string, password: string): Promise<string> {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  return data.session.access_token;
}

async function getInvoice(token: string | null, invoiceId: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (token) headers.authorization = `Bearer ${token}`;
  return fetch(`${APP_URL}/api/invoices/${invoiceId}`, { headers });
}

describe("invoice authorization matrix", () => {
  let alice: string;
  let bob: string;

  beforeAll(async () => {
    alice = await tokenFor("alice@tenant-a.test", "alice-password-123");
    bob = await tokenFor("bob@tenant-b.test", "bob-password-123");
  });

  it("Alice reads her own invoice: ALLOW", async () => {
    expect((await getInvoice(alice, SEED.alice.invoiceId)).status).toBe(200);
  });

  it("Bob reads his own invoice: ALLOW", async () => {
    expect((await getInvoice(bob, SEED.bob.invoiceId)).status).toBe(200);
  });

  it("Alice reads Bob's invoice (other tenant): DENY", async () => {
    const res = await getInvoice(alice, SEED.bob.invoiceId);
    expect([403, 404]).toContain(res.status);
  });

  it("Bob reads Alice's invoice (other tenant): DENY", async () => {
    const res = await getInvoice(bob, SEED.alice.invoiceId);
    expect([403, 404]).toContain(res.status);
  });

  it("Anonymous reads any invoice: DENY", async () => {
    expect((await getInvoice(null, SEED.alice.invoiceId)).status).toBe(401);
  });
});
