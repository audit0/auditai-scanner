/**
 * Security regression test for fixture 034. The catalogue is public to read and closed to write.
 * Seed: the admin user carries app_metadata.role = "admin"; alice is a plain member.
 */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";

async function sessionCookieFor(email: string, password: string): Promise<string> {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  return `sb-access-token=${data.session.access_token}; sb-refresh-token=${data.session.refresh_token}`;
}

async function productCount(): Promise<number> {
  const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });
  const { count } = await admin.from("products").select("id", { count: "exact", head: true });
  return count ?? 0;
}

function post(cookie: string | null): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (cookie) headers.cookie = cookie;
  return fetch(`${APP_URL}/api/products`, {
    method: "POST",
    headers,
    body: JSON.stringify({ name: "injected", price_cents: 1 }),
  });
}

describe("public catalogue", () => {
  let alice: string;
  let admin: string;

  beforeAll(async () => {
    alice = await sessionCookieFor("alice@tenant-a.test", "alice-password-123");
    admin = await sessionCookieFor("admin@tenant-a.test", "admin-password-123");
  });

  it("anonymous read of the catalogue: ALLOW", async () => {
    expect((await fetch(`${APP_URL}/api/products`)).status).toBe(200);
  });

  it("anonymous insert into the catalogue: DENY", async () => {
    const before = await productCount();
    expect((await post(null)).status).toBe(401);
    expect(await productCount()).toBe(before);
  });

  it("a signed-in member inserts into the catalogue: DENY", async () => {
    const before = await productCount();
    expect((await post(alice)).status).toBe(401);
    expect(await productCount()).toBe(before);
  });

  it("the operator inserts into the catalogue: ALLOW", async () => {
    const before = await productCount();
    expect((await post(admin)).status).toBe(201);
    expect(await productCount()).toBe(before + 1);
  });
});
