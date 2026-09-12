/**
 * Security regression test for fixture 025. Server actions are invoked through the page in the
 * sandbox harness, the same shape as fixture 009. This test is DENY/ALLOW style and is not
 * executed directly by this repository's CI; it documents what Audit AI must generate.
 *
 * Expected on the vulnerable app: Bob's call deletes Alice's note (test FAILS: row is gone).
 * Expected on the secure app: the note survives, deleteNote throws (test PASSES).
 */
import { createClient } from "@supabase/supabase-js";
import { describe, expect, it } from "vitest";

const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<
  "alice" | "bob",
  { noteId: string }
>;
// Provided by the sandbox harness: a command that signs in as Bob and calls deleteNote(id).
const invokeAsBob = process.env.INVOKE_ACTION_AS_BOB;

describe("deleteNote", () => {
  it("Bob cannot delete Alice's note: DENY", async () => {
    expect(invokeAsBob, "harness must provide INVOKE_ACTION_AS_BOB").toBeTruthy();
    const { execSync } = await import("node:child_process");
    try {
      execSync(`${invokeAsBob} ${SEED.alice.noteId}`, { stdio: "ignore" });
    } catch {
      // The secure action throws on a foreign note; that is the expected outcome.
    }
    const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });
    const { data } = await admin.from("notes").select("id").eq("id", SEED.alice.noteId).maybeSingle();
    expect(data?.id).toBe(SEED.alice.noteId);
  });

  it("Alice can delete her own note: ALLOW", async () => {
    const invokeAsAlice = process.env.INVOKE_ACTION_AS_ALICE;
    expect(invokeAsAlice, "harness must provide INVOKE_ACTION_AS_ALICE").toBeTruthy();
    const { execSync } = await import("node:child_process");
    execSync(`${invokeAsAlice} ${SEED.alice.noteId}`, { stdio: "ignore" });
    const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });
    const { data } = await admin.from("notes").select("id").eq("id", SEED.alice.noteId).maybeSingle();
    expect(data).toBeNull();
  });
});
