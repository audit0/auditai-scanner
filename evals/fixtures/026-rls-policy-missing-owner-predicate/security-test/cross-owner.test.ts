/** Identity matrix for fixture 026: with the policy fixed, Alice must not read Bob's project. */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY ?? "";
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<
  "alice" | "bob",
  { projectId: string }
>;

async function tokenFor(email: string, password: string): Promise<string> {
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  return data.session.access_token;
}

// The route reads the session from cookies via @supabase/ssr; the test drives it with the
// equivalent bearer token against the same route, which the harness's cookie shim accepts.
const get = (token: string, id: string) =>
  fetch(`${APP_URL}/api/projects/${id}`, { headers: { authorization: `Bearer ${token}` } });

describe("projects RLS owner scope", () => {
  let alice = "";
  let bob = "";
  beforeAll(async () => {
    alice = await tokenFor("alice@example.test", "alice-password-123");
    bob = await tokenFor("bob@example.test", "bob-password-123");
  });
  it("Alice reads her own project: ALLOW", async () =>
    expect((await get(alice, SEED.alice.projectId)).status).toBe(200));
  it("Bob reads his own project: ALLOW", async () =>
    expect((await get(bob, SEED.bob.projectId)).status).toBe(200));
  it("Alice reads Bob's project: DENY", async () =>
    expect((await get(alice, SEED.bob.projectId)).status).toBe(404));
  it("Bob reads Alice's project: DENY", async () =>
    expect((await get(bob, SEED.alice.projectId)).status).toBe(404));
});
