/**
 * Security regression test for fixture 015: an identity matrix against the running app, no mocks.
 * Each user first uploads a file into their own folder with their own session (the storage policies
 * allow exactly that), then asks the app to download files by path.
 *
 * Expected on the vulnerable app: "Alice -> Bob's file" returns 200 (test FAILS).
 * Expected on the secure app: 404 (test PASSES). Own-file downloads must stay 200.
 * Needs storage-api in the local Supabase stack (the sandbox excludes it today: scan-only fixture).
 */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<
  "alice" | "bob",
  { userId: string }
>;

async function tokenFor(email: string, password: string): Promise<string> {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  return data.session.access_token;
}

/** Uploads into the caller's own folder with the caller's own session. */
async function uploadOwn(token: string, path: string, text: string): Promise<void> {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, {
    auth: { persistSession: false },
    global: { headers: { Authorization: `Bearer ${token}` } },
  });
  const { error } = await sb.storage
    .from("documents")
    .upload(path, new Blob([text], { type: "text/plain" }));
  if (error && !/exists/i.test(error.message)) throw error;
}

async function download(token: string | null, path: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (token) headers.authorization = `Bearer ${token}`;
  return fetch(`${APP_URL}/api/documents/download?path=${encodeURIComponent(path)}`, { headers });
}

describe("document download authorization matrix", () => {
  let alice: string;
  let bob: string;
  const aliceFile = (): string => `${SEED.alice.userId}/report.txt`;
  const bobFile = (): string => `${SEED.bob.userId}/report.txt`;

  beforeAll(async () => {
    alice = await tokenFor("alice@tenant-a.test", "alice-password-123");
    bob = await tokenFor("bob@tenant-b.test", "bob-password-123");
    await uploadOwn(alice, aliceFile(), "alice's report");
    await uploadOwn(bob, bobFile(), "bob's report");
  });

  it("Alice downloads her own file: ALLOW", async () => {
    const res = await download(alice, aliceFile());
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("alice's report");
  });

  it("Bob downloads his own file: ALLOW", async () => {
    expect((await download(bob, bobFile())).status).toBe(200);
  });

  it("Alice downloads Bob's file (other user): DENY", async () => {
    const res = await download(alice, bobFile());
    expect([403, 404]).toContain(res.status);
  });

  it("Bob downloads Alice's file (other user): DENY", async () => {
    const res = await download(bob, aliceFile());
    expect([403, 404]).toContain(res.status);
  });

  it("Alice climbs out of her folder with ../: DENY", async () => {
    const res = await download(alice, `${SEED.alice.userId}/../${bobFile()}`);
    expect([400, 403, 404]).toContain(res.status);
  });

  it("Anonymous downloads any file: DENY", async () => {
    expect((await download(null, aliceFile())).status).toBe(401);
  });
});
