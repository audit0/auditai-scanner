/** Identity matrix for fixture 027: with RLS enabled, Alice must not read Bob's document. */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY ?? "";
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<
  "alice" | "bob",
  { documentId: string }
>;

async function tokenFor(email: string, password: string): Promise<string> {
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  return data.session.access_token;
}
const get = (token: string, id: string) =>
  fetch(`${APP_URL}/api/documents/${id}`, { headers: { authorization: `Bearer ${token}` } });

describe("documents RLS", () => {
  let alice = "";
  beforeAll(async () => {
    alice = await tokenFor("alice@example.test", "alice-password-123");
  });
  it("Alice reads her own document: ALLOW", async () =>
    expect((await get(alice, SEED.alice.documentId)).status).toBe(200));
  it("Alice reads Bob's document: DENY", async () =>
    expect((await get(alice, SEED.bob.documentId)).status).toBe(404));
  it("anon key reads nothing through PostgREST directly: DENY", async () => {
    const sb = createClient(SUPABASE_URL, ANON_KEY);
    const { data } = await sb.from("documents").select("id");
    expect(data ?? []).toHaveLength(0);
  });
});
