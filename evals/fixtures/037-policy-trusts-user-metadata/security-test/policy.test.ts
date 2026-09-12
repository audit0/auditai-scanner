/**
 * Identity matrix for fixture 037. Alice writes her own user_metadata and asks for Bob's notes:
 * with the app_metadata policy the claim she controls decides nothing.
 */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY ?? "";
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<"alice" | "bob", { noteId: string }>;

async function signIn(email: string, password: string) {
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  return sb;
}

describe("notes policy and user_metadata", () => {
  let alice: Awaited<ReturnType<typeof signIn>>;
  beforeAll(async () => {
    alice = await signIn("alice@tenant-a.test", "alice-password-123");
    await alice.auth.updateUser({ data: { is_admin: true, role: "admin" } });
    await alice.auth.refreshSession();
  });

  it("Alice reads her own note: ALLOW", async () => {
    const { data } = await alice.from("notes").select("id").eq("id", SEED.alice.noteId);
    expect(data ?? []).toHaveLength(1);
  });

  it("Alice grants herself is_admin and reads Bob's note: DENY", async () => {
    const { data } = await alice.from("notes").select("id").eq("id", SEED.bob.noteId);
    expect(data ?? []).toHaveLength(0);
  });

  it("the anon key reads no notes at all: DENY", async () => {
    const sb = createClient(SUPABASE_URL, ANON_KEY);
    const { data } = await sb.from("notes").select("id");
    expect(data ?? []).toHaveLength(0);
  });
});
