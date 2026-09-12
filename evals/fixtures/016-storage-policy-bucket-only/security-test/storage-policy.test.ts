/**
 * Security regression test for fixture 016: an identity matrix against the running app and the Storage
 * API itself, no mocks. Each user first uploads a file into their own folder with their own session
 * (the upload policy allows exactly that).
 *
 * Expected on the vulnerable schema: "Alice -> Bob's file" returns 200 through the app and the
 * Storage API hands out the file (tests FAIL). Expected on the secure schema: 404 / storage error
 * (tests PASS). Own-file downloads must keep working.
 * Needs storage-api in the local Supabase stack (the sandbox excludes it today: scan-only fixture).
 */
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
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

function asUser(token: string): SupabaseClient {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  return createClient(SUPABASE_URL, ANON_KEY, {
    auth: { persistSession: false },
    global: { headers: { Authorization: `Bearer ${token}` } },
  });
}

async function uploadOwn(token: string, path: string, text: string): Promise<void> {
  const { error } = await asUser(token)
    .storage.from("documents")
    .upload(path, new Blob([text], { type: "text/plain" }));
  if (error && !/exists/i.test(error.message)) throw error;
}

async function download(token: string | null, path: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (token) headers.authorization = `Bearer ${token}`;
  return fetch(`${APP_URL}/api/documents/download?path=${encodeURIComponent(path)}`, { headers });
}

describe("storage read policy matrix", () => {
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

  it("Alice downloads her own file through the app: ALLOW", async () => {
    const res = await download(alice, aliceFile());
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("alice's report");
  });

  it("Bob downloads his own file through the app: ALLOW", async () => {
    expect((await download(bob, bobFile())).status).toBe(200);
  });

  it("Alice downloads Bob's file through the app: DENY", async () => {
    expect([403, 404]).toContain((await download(alice, bobFile())).status);
  });

  it("Alice downloads Bob's file straight from the Storage API: DENY", async () => {
    const { data } = await asUser(alice).storage.from("documents").download(bobFile());
    expect(data).toBeNull();
  });

  it("Alice lists Bob's folder straight from the Storage API: DENY", async () => {
    const { data } = await asUser(alice).storage.from("documents").list(SEED.bob.userId);
    expect(data ?? []).toEqual([]);
  });

  it("Anonymous downloads any file: DENY", async () => {
    expect((await download(null, aliceFile())).status).toBe(401);
  });
});
