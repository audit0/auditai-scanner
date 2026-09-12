/** Fixture 010: batch lookup must not return other tenants' invoices. */
import { createClient } from "@supabase/supabase-js";
import { describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY ?? "";
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<"alice" | "bob", { invoiceId: string }>;

async function batchIdsAsAlice(): Promise<string[]> {
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email: "alice@tenant-a.test", password: "alice-password-123" });
  if (error || !data.session) throw error ?? new Error("no session");
  const res = await fetch(`${APP_URL}/api/invoices/batch`, {
    method: "POST",
    headers: { authorization: `Bearer ${data.session.access_token}`, "content-type": "application/json" },
    body: JSON.stringify({ ids: [SEED.alice.invoiceId, SEED.bob.invoiceId] }),
  });
  const body = (await res.json()) as { invoices?: Array<{ id: string }> };
  return (body.invoices ?? []).map((i) => i.id);
}

describe("POST /api/invoices/batch", () => {
  it("ALLOW: Alice gets her own invoice from the batch", async () => {
    expect(await batchIdsAsAlice()).toContain(SEED.alice.invoiceId);
  });

  it("DENY: the batch never returns Bob's invoice to Alice", async () => {
    expect(await batchIdsAsAlice()).not.toContain(SEED.bob.invoiceId);
  });
});
