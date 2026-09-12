/**
 * Security regression test for fixture 022. Identity matrix executed against the running app,
 * no mocks.
 *
 * Expected on the vulnerable app: Alice posting Tenant B's id gets Tenant B's invoices (test FAILS).
 * Expected on the secure app: Alice always gets only Tenant A's invoices, whatever she posts.
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

async function tokenFor(email: string, password: string): Promise<string> {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  return data.session.access_token;
}

async function searchInvoices(token: string, tenantId: string): Promise<Response> {
  return fetch(`${APP_URL}/api/invoices`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ tenantId }),
  });
}

describe("POST /api/invoices tenant scope", () => {
  let alice: string;

  beforeAll(async () => {
    alice = await tokenFor("alice@tenant-a.test", "alice-password-123");
  });

  it("Alice searching her own tenant gets her invoices: ALLOW", async () => {
    const res = await searchInvoices(alice, SEED.alice.tenantId);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { invoices: Array<{ tenant_id: string }> };
    for (const inv of body.invoices) expect(inv.tenant_id).toBe(SEED.alice.tenantId);
  });

  it("Alice posting Bob's tenant id must not return Tenant B invoices: DENY", async () => {
    const res = await searchInvoices(alice, SEED.bob.tenantId);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { invoices: Array<{ tenant_id: string }> };
    for (const inv of body.invoices) expect(inv.tenant_id).not.toBe(SEED.bob.tenantId);
  });

  it("Anonymous search: DENY", async () => {
    const res = await fetch(`${APP_URL}/api/invoices`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId: SEED.alice.tenantId }),
    });
    expect(res.status).toBe(401);
  });
});
