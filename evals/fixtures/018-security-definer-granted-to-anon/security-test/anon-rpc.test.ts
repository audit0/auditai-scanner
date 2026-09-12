/**
 * Security regression test for fixture 018: an identity matrix against the running app and PostgREST,
 * no mocks. The dashboard totals come from public.tenant_invoice_totals(p_tenant_id).
 *
 * Expected on the vulnerable schema: anonymous callers and other tenants read Bob's totals (tests
 * FAIL). Expected on the secure schema: anonymous callers are refused and other tenants count nothing
 * (tests PASS). A member's own totals must stay visible.
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

interface Totals {
  invoice_count: number;
  total_cents: number;
}

async function tokenFor(email: string, password: string): Promise<string> {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  return data.session.access_token;
}

async function totalsViaApp(token: string | null, tenantId: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (token) headers.authorization = `Bearer ${token}`;
  return fetch(`${APP_URL}/api/tenants/${tenantId}/totals`, { headers });
}

describe("tenant totals through a SECURITY DEFINER function", () => {
  let alice: string;

  beforeAll(async () => {
    alice = await tokenFor("alice@tenant-a.test", "alice-password-123");
  });

  it("Alice reads her own tenant's totals: ALLOW", async () => {
    const res = await totalsViaApp(alice, SEED.alice.tenantId);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { totals: Totals };
    expect(Number(body.totals.invoice_count)).toBeGreaterThan(0);
  });

  it("Alice reads Bob's tenant totals through the app: DENY", async () => {
    const res = await totalsViaApp(alice, SEED.bob.tenantId);
    if (res.status === 200) {
      const body = (await res.json()) as { totals: Totals };
      expect(Number(body.totals.invoice_count)).toBe(0);
    } else {
      expect([403, 404]).toContain(res.status);
    }
  });

  it("Anonymous visitor calls the function with the anon key: DENY", async () => {
    if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
    const anon = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
    const { data } = await anon.rpc("tenant_invoice_totals", { p_tenant_id: SEED.bob.tenantId });
    const rows = (Array.isArray(data) ? data : []) as Totals[];
    expect(rows.every((r) => Number(r.invoice_count) === 0)).toBe(true);
  });

  it("Anonymous request to the app: DENY", async () => {
    expect((await totalsViaApp(null, SEED.bob.tenantId)).status).toBe(401);
  });
});
