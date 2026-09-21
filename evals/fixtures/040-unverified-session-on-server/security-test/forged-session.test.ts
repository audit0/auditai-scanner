/**
 * Security regression test for fixture 040. The hole is not in the database: Row Level Security and
 * the policies are the same in both variants. It is that the server decides who is calling from a
 * token it never verified, so the test edits the token's payload instead of attacking the schema.
 *
 * DENY: Alice presents a cookie whose `sub` has been changed to Bob's id. The signature no longer
 * matches. A server that calls getUser() or getClaims() rejects it; a server that calls getSession()
 * believes it and scopes the query to Bob.
 * ALLOW: both users still see their own orders with their genuine cookies.
 */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://127.0.0.1:3000";
const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<
  "alice" | "bob",
  { userId: string; item: string }
>;

interface Session {
  accessToken: string;
  refreshToken: string;
}

async function signIn(email: string, password: string): Promise<Session> {
  if (!ANON_KEY) throw new Error("SUPABASE_ANON_KEY is required");
  const sb = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("no session");
  return { accessToken: data.session.access_token, refreshToken: data.session.refresh_token };
}

const b64url = (s: string): string =>
  Buffer.from(s).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/** The same token with its `sub` claim replaced. The signature is left as it was, so it is wrong. */
function withSubject(accessToken: string, sub: string): string {
  const [header, payload, signature] = accessToken.split(".");
  if (!header || !payload || !signature) throw new Error("not a JWT");
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Record<
    string,
    unknown
  >;
  return [header, b64url(JSON.stringify({ ...claims, sub })), signature].join(".");
}

const cookie = (s: Session): string =>
  `sb-access-token=${s.accessToken}; sb-refresh-token=${s.refreshToken}`;

const orders = (cookieHeader: string): Promise<Response> =>
  fetch(`${APP_URL}/api/orders`, { headers: { cookie: cookieHeader } });

describe("a session the server never verified", () => {
  let alice: Session;
  let bob: Session;

  beforeAll(async () => {
    alice = await signIn("alice@tenant-a.test", "alice-password-123");
    bob = await signIn("bob@tenant-b.test", "bob-password-123");
  });

  it("Alice claims Bob's id in her own cookie: DENY", async () => {
    const forged = cookie({ ...alice, accessToken: withSubject(alice.accessToken, SEED.bob.userId) });
    const res = await orders(forged);
    const body = (await res.json().catch(() => ({}))) as { orders?: Array<{ item: string }> };
    const items = body.orders?.map((o) => o.item) ?? [];
    expect(items).not.toContain(SEED.bob.item);
    expect(res.status).toBe(401);
  });

  it("Alice sees her own orders: ALLOW", async () => {
    const res = await orders(cookie(alice));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { orders: Array<{ item: string }> };
    expect(body.orders.map((o) => o.item)).toEqual([SEED.alice.item]);
  });

  it("Bob sees his own orders: ALLOW", async () => {
    const res = await orders(cookie(bob));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { orders: Array<{ item: string }> };
    expect(body.orders.map((o) => o.item)).toEqual([SEED.bob.item]);
  });
});
