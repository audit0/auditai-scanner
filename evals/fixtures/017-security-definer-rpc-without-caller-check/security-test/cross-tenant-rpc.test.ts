/**
 * Security regression test for fixture 017: an identity matrix against the running app and PostgREST,
 * no mocks. The app reads invoices through supabase.rpc("get_invoice"), a SECURITY DEFINER function.
 *
 * Expected on the vulnerable schema: "Alice -> Bob's invoice" returns 200 through the app, and the RPC
 * endpoint hands the row out directly (tests FAIL). Expected on the secure schema: 404 and no row
 * (tests PASS). Own-invoice reads must stay 200.
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

/** Calls the function straight through PostgREST, as any signed-in user can. */
async function rpcAs(token: string, invoiceId: string): Promise<unknown[]> {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, {
    auth: { persistSession: false },
    global: { headers: { Authorization: `Bearer ${token}` } },
  });
  const { data } = await sb.rpc("get_invoice", { invoice_id: invoiceId });
  return Array.isArray(data) ? data : [];
}

describe("invoice lookup through a SECURITY DEFINER function", () => {
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

  it("Alice reads Bob's invoice through the app: DENY", async () => {
    expect([403, 404]).toContain((await getInvoice(alice, SEED.bob.invoiceId)).status);
  });

  it("Bob reads Alice's invoice through the app: DENY", async () => {
    expect([403, 404]).toContain((await getInvoice(bob, SEED.alice.invoiceId)).status);
  });

  it("Alice calls get_invoice for Bob's invoice straight through PostgREST: DENY", async () => {
    expect(await rpcAs(alice, SEED.bob.invoiceId)).toEqual([]);
  });

  it("Anonymous reads any invoice: DENY", async () => {
    expect((await getInvoice(null, SEED.alice.invoiceId)).status).toBe(401);
  });
});
