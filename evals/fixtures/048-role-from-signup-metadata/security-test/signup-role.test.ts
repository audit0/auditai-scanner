/**
 * Security regression test for fixture 048: sign-ups against the running Auth API, PostgREST and the
 * app, no mocks. user_roles.role decides who may call /api/admin/users.
 *
 * Expected on the vulnerable schema: an account created with options.data.role = 'admin' is an admin
 * (tests FAIL). Expected on the secure schema: it is a member and the admin route answers 403 (tests
 * PASS). A plain sign-up must still get a role row.
 */
import { randomUUID } from "node:crypto";
import { createClient } from "@supabase/supabase-js";
import { describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY;

async function signUp(data?: Record<string, string>) {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const email = `signup-${randomUUID()}@fixture.test`;
  const { data: res, error } = await sb.auth.signUp({
    email,
    password: `pw-${randomUUID()}`,
    ...(data ? { options: { data } } : {}),
  });
  if (error || !res.session || !res.user) throw error ?? new Error("no session (email confirmation on?)");
  return { sb, token: res.session.access_token, id: res.user.id };
}

describe("fixture 048: role from sign-up metadata", () => {
  it("A plain sign-up gets the member role: ALLOW", async () => {
    const u = await signUp();
    const { data } = await u.sb.from("user_roles").select("role").eq("user_id", u.id).single();
    expect(data?.role).toBe("member");
  });

  it("A sign-up that asks for admin is not an admin: DENY", async () => {
    const u = await signUp({ role: "admin" });
    const { data } = await u.sb.rpc("is_admin");
    expect(data).not.toBe(true);
  });

  it("That account is refused by the admin route: DENY", async () => {
    const u = await signUp({ role: "admin" });
    const res = await fetch(`${APP_URL}/api/admin/users`, {
      headers: { authorization: `Bearer ${u.token}` },
    });
    expect(res.status).toBe(403);
  });
});
