/**
 * Security regression test for fixture 030. The purge endpoint must refuse callers that do not
 * present the scheduler's secret, and must still run for the scheduler. Seeded rows: one finished
 * job older than the retention window per tenant.
 */
import { createClient } from "@supabase/supabase-js";
import { describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const CRON_SECRET = process.env.CRON_SECRET ?? "local-cron-secret";
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<
  "alice" | "bob",
  { expiredJobId: string }
>;

async function jobExists(id: string): Promise<boolean> {
  const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });
  const { data } = await admin.from("jobs").select("id").eq("id", id).maybeSingle();
  return data?.id === id;
}

async function purge(authorization: string | null): Promise<Response> {
  const headers: Record<string, string> = {};
  if (authorization) headers.authorization = authorization;
  return fetch(`${APP_URL}/api/cron/purge`, { method: "POST", headers });
}

describe("POST /api/cron/purge", () => {
  it("DENY: an anonymous call is refused and deletes nothing", async () => {
    expect((await purge(null)).status).toBe(401);
    expect(await jobExists(SEED.alice.expiredJobId)).toBe(true);
    expect(await jobExists(SEED.bob.expiredJobId)).toBe(true);
  });

  it("DENY: a wrong secret is refused and deletes nothing", async () => {
    expect((await purge("Bearer not-the-secret")).status).toBe(401);
    expect(await jobExists(SEED.alice.expiredJobId)).toBe(true);
  });

  it("ALLOW: the scheduler's secret runs the purge", async () => {
    expect((await purge(`Bearer ${CRON_SECRET}`)).status).toBe(200);
    expect(await jobExists(SEED.alice.expiredJobId)).toBe(false);
  });
});
