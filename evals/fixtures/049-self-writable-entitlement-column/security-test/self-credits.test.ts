/**
 * Security regression test for fixture 049: an identity matrix against the running app and PostgREST,
 * no mocks. profiles.credits decides how many paid exports a user may run.
 *
 * Expected on the vulnerable schema: Alice sets her own credits and keeps exporting (tests FAIL).
 * Expected on the secure schema: the credits update is refused and exports stop at zero (tests PASS).
 * Editing her own display name must keep working.
 */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY;

async function signIn(email: string, password: string) {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session || !data.user) throw error ?? new Error("no session");
  return { sb, token: data.session.access_token, id: data.user.id };
}

async function credits(alice: Awaited<ReturnType<typeof signIn>>): Promise<number | undefined> {
  const { data } = await alice.sb.from("profiles").select("credits").eq("id", alice.id).single();
  return data?.credits;
}

describe("fixture 049: self-writable entitlement column", () => {
  let alice: Awaited<ReturnType<typeof signIn>>;

  beforeAll(async () => {
    alice = await signIn("alice@tenant-a.test", "alice-password-123");
  });

  it("Alice edits her own display name: ALLOW", async () => {
    const { error } = await alice.sb
      .from("profiles")
      .update({ full_name: "Alice A." })
      .eq("id", alice.id);
    expect(error).toBeNull();
  });

  it("Alice sets her own credits: DENY", async () => {
    const before = await credits(alice);
    await alice.sb.from("profiles").update({ credits: 1000000 }).eq("id", alice.id);
    expect(await credits(alice)).toBe(before);
  });

  it("Alice exports after spending her credits: DENY", async () => {
    const left = (await credits(alice)) ?? 0;
    const export_ = () =>
      fetch(`${APP_URL}/api/invoices/export`, {
        method: "POST",
        headers: { authorization: `Bearer ${alice.token}` },
      });
    for (let i = 0; i < left; i += 1) await export_();
    const res = await export_();
    expect(res.status).toBe(402);
  });
});
