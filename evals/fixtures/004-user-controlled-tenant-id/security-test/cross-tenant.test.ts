/** Fixture 004: Alice must never receive Tenant B invoices, whatever ?tenant= she sends. */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY ?? "";
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<"alice" | "bob", { tenantId: string; invoiceId: string }>;

async function tokenFor(email: string, password: string): Promise<string> {
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  return data.session.access_token;
}

describe("tenant scoping", () => {
  let alice = "";
  beforeAll(async () => {
    alice = await tokenFor("alice@tenant-a.test", "alice-password-123");
  });
  it("DENY: Alice asking for Tenant B never gets Tenant B rows", async () => {
    const res = await fetch(`${APP_URL}/api/invoices?tenant=${SEED.bob.tenantId}`, { headers: { authorization: `Bearer ${alice}` } });
    const body = (await res.json()) as { invoices?: Array<{ id: string; tenant_id: string }> };
    expect((body.invoices ?? []).some((i) => i.tenant_id === SEED.bob.tenantId)).toBe(false);
  });
  it("ALLOW: Alice gets her own invoices", async () => {
    const res = await fetch(`${APP_URL}/api/invoices?tenant=${SEED.alice.tenantId}`, { headers: { authorization: `Bearer ${alice}` } });
    const body = (await res.json()) as { invoices?: Array<{ id: string }> };
    expect((body.invoices ?? []).map((i) => i.id)).toContain(SEED.alice.invoiceId);
  });
});
