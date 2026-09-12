/**
 * Security regression test for fixture 035. Two tenants, one API key each. A caller presenting
 * tenant A's key must only ever see and touch tenant A's key row, whatever `?key=` names.
 * Seed: FIXTURE_SEED_JSON carries, per tenant, the plaintext key and the key row id.
 */
import { createClient } from "@supabase/supabase-js";
import { describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<
  "alice" | "bob",
  { apiKey: string; keyId: string; tenantId: string }
>;

async function me(apiKey: string | null, keyParam?: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (apiKey) headers.authorization = `Bearer ${apiKey}`;
  const url = new URL(`${APP_URL}/api/v1/me`);
  if (keyParam) url.searchParams.set("key", keyParam);
  return fetch(url, { headers });
}

async function lastUsedAt(keyId: string): Promise<string | null> {
  const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });
  const { data } = await admin.from("api_keys").select("last_used_at").eq("id", keyId).maybeSingle();
  return data?.last_used_at ?? null;
}

describe("GET /api/v1/me", () => {
  it("DENY: no key is refused", async () => {
    expect((await me(null)).status).toBe(401);
  });

  it("DENY: Alice naming Bob's key row gets her own row, and Bob's row is not touched", async () => {
    const before = await lastUsedAt(SEED.bob.keyId);
    const res = await me(SEED.alice.apiKey, SEED.bob.keyId);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { tenant: string; key: { id: string } };
    expect(body.tenant).toBe(SEED.alice.tenantId);
    expect(body.key.id).toBe(SEED.alice.keyId);
    expect(await lastUsedAt(SEED.bob.keyId)).toBe(before);
  });

  it("ALLOW: Alice sees her own key row", async () => {
    const res = await me(SEED.alice.apiKey);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { tenant: string; key: { id: string } };
    expect(body.tenant).toBe(SEED.alice.tenantId);
    expect(body.key.id).toBe(SEED.alice.keyId);
  });
});
