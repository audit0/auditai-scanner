/**
 * Security regression test for fixture 047: an identity matrix against the running app and PostgREST,
 * no mocks. profiles.role decides who may call /api/admin/users.
 *
 * Expected on the vulnerable schema: Alice sets her own role to admin and then lists every tenant's
 * users (tests FAIL). Expected on the secure schema: the role update is refused and the admin route
 * answers 403 (tests PASS). Editing her own display name must keep working.
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

describe("fixture 047: self-assignable role column", () => {
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

  it("Alice sets her own role to admin: DENY", async () => {
    await alice.sb.from("profiles").update({ role: "admin" }).eq("id", alice.id);
    const { data } = await alice.sb.from("profiles").select("role").eq("id", alice.id).single();
    expect(data?.role).not.toBe("admin");
  });

  it("Alice calls the admin route after trying to promote herself: DENY", async () => {
    const res = await fetch(`${APP_URL}/api/admin/users`, {
      headers: { authorization: `Bearer ${alice.token}` },
    });
    expect(res.status).toBe(403);
  });
});
