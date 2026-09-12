/**
 * Identity matrix for fixture 038. The policies on `pages` only apply once RLS is enabled; until
 * then the anon key reads the whole table straight through PostgREST.
 */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY ?? "";
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<"alice" | "bob", { pageId: string }>;

async function signIn(email: string, password: string) {
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  return sb;
}

describe("pages RLS", () => {
  let alice: Awaited<ReturnType<typeof signIn>>;
  beforeAll(async () => {
    alice = await signIn("alice@tenant-a.test", "alice-password-123");
  });

  it("Alice reads a page in her own workspace: ALLOW", async () => {
    const { data } = await alice.from("pages").select("id").eq("id", SEED.alice.pageId);
    expect(data ?? []).toHaveLength(1);
  });

  it("Alice reads a page in Bob's workspace: DENY", async () => {
    const { data } = await alice.from("pages").select("id").eq("id", SEED.bob.pageId);
    expect(data ?? []).toHaveLength(0);
  });

  it("the anon key reads pages through PostgREST directly: DENY", async () => {
    const sb = createClient(SUPABASE_URL, ANON_KEY);
    const { data } = await sb.from("pages").select("id");
    expect(data ?? []).toHaveLength(0);
  });
});
