/**
 * Security regression test for fixture 029: an identity matrix against the running app, no mocks.
 * Each user first writes a note into their own account with their own session (the insert policy
 * allows it), then asks the app for their own and the other account's note.
 *
 * Expected on the vulnerable schema: "Alice -> Bob's note" returns 200 (test FAILS).
 * Expected on the secure schema: 404 (test PASSES). Own-account reads must stay 200.
 */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<
  "alice" | "bob",
  { userId: string; tenantId: string }
>;

async function tokenFor(email: string, password: string): Promise<string> {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  return data.session.access_token;
}

/** Writes a note into the caller's own account with the caller's own session. */
async function writeOwnNote(token: string, who: "alice" | "bob"): Promise<string> {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, {
    auth: { persistSession: false },
    global: { headers: { Authorization: `Bearer ${token}` } },
  });
  const { data, error } = await sb
    .from("notes")
    .insert({ account_id: SEED[who].tenantId, author_id: SEED[who].userId, body: `${who}'s note` })
    .select("id")
    .single();
  if (error || !data) throw error ?? new Error("note insert failed");
  return data.id as string;
}

async function getNote(token: string | null, id: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (token) headers.authorization = `Bearer ${token}`;
  return fetch(`${APP_URL}/api/notes/${id}`, { headers });
}

describe("account notes authorization matrix", () => {
  let alice: string;
  let bob: string;
  let aliceNote: string;
  let bobNote: string;

  beforeAll(async () => {
    alice = await tokenFor("alice@tenant-a.test", "alice-password-123");
    bob = await tokenFor("bob@tenant-b.test", "bob-password-123");
    aliceNote = await writeOwnNote(alice, "alice");
    bobNote = await writeOwnNote(bob, "bob");
  });

  it("Alice reads her own account's note: ALLOW", async () => {
    expect((await getNote(alice, aliceNote)).status).toBe(200);
  });

  it("Bob reads his own account's note: ALLOW", async () => {
    expect((await getNote(bob, bobNote)).status).toBe(200);
  });

  it("Alice reads Bob's account note: DENY", async () => {
    expect([403, 404]).toContain((await getNote(alice, bobNote)).status);
  });

  it("Bob reads Alice's account note: DENY", async () => {
    expect([403, 404]).toContain((await getNote(bob, aliceNote)).status);
  });

  it("Anonymous reads any note: DENY", async () => {
    expect((await getNote(null, aliceNote)).status).toBe(401);
  });
});
