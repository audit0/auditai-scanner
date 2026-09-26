/**
 * Security regression test for fixture 045: an identity matrix against the running app and PostgREST,
 * no mocks. Invoice search comes from public.search_invoices(p_customer).
 *
 * Expected on the vulnerable schema: an injected search returns Bob's invoices to Alice and to an
 * anonymous caller (tests FAIL). Expected on the secure schema: the quote is matched literally, anon is
 * refused, and nothing of Bob's tenant comes back (tests PASS). Alice's own search must keep working.
 */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<
  "alice" | "bob",
  { tenantId: string }
>;

/** Closes the ILIKE literal and comments out the rest of the statement, tenant filter included. */
const INJECTION = "%' or true --";

interface Invoice {
  tenant_id: string;
}

async function tokenFor(email: string, password: string): Promise<string> {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  return data.session.access_token;
}

async function searchViaApp(token: string | null, q: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (token) headers.authorization = `Bearer ${token}`;
  return fetch(`${APP_URL}/api/invoices/search?q=${encodeURIComponent(q)}`, { headers });
}

describe("fixture 045: SQL injection through search_invoices", () => {
  let alice: string;

  beforeAll(async () => {
    alice = await tokenFor("alice@tenant-a.test", "alice-password-123");
  });

  it("Alice searches her own tenant's invoices: ALLOW", async () => {
    const res = await searchViaApp(alice, "");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { invoices: Invoice[] };
    expect(body.invoices.length).toBeGreaterThan(0);
    expect(body.invoices.every((i) => i.tenant_id === SEED.alice.tenantId)).toBe(true);
  });

  it("Alice sends an injected search through the app: DENY", async () => {
    const res = await searchViaApp(alice, INJECTION);
    if (res.status === 200) {
      const body = (await res.json()) as { invoices: Invoice[] };
      expect(body.invoices.some((i) => i.tenant_id === SEED.bob.tenantId)).toBe(false);
    } else {
      expect([400, 403, 404]).toContain(res.status);
    }
  });

  it("Anonymous visitor sends an injected search with the anon key: DENY", async () => {
    if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
    const anon = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
    const { data } = await anon.rpc("search_invoices", { p_customer: INJECTION });
    const rows = (Array.isArray(data) ? data : []) as Invoice[];
    expect(rows).toEqual([]);
  });

  it("Anonymous request to the app: DENY", async () => {
    expect((await searchViaApp(null, INJECTION)).status).toBe(401);
  });
});
