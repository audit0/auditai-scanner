# 040 — the server authorizes on a session it never verified

Both variants have the same database: `orders` has Row Level Security on and two policies that let a
user reach only their own rows. The difference is one call in `app/api/orders/route.ts`.

- `vulnerable/` establishes the caller with `supabase.auth.getSession()`. That call reads the session
  out of the cookie and does not revalidate it, so `session.user.id` is whatever the browser sent.
  A user who edits the `sub` claim of their own token gets another user's orders.
- `secure/` uses `supabase.auth.getUser()`, which asks the Auth server whether the token is genuine.
  `getClaims()`, which verifies the token's signature, would do as well.

Supabase's own guidance is the source: "Never trust `supabase.auth.getSession()` inside server code.
It reads the session out of the cookie without revalidating it."

Why the route reads through the service-role client in both variants: that is what makes the
unverified session decide anything. Through the caller's own cookie client the request still passes
PostgREST, which refuses a token whose signature does not match, and then Row Level Security, where a
forged id buys nothing. The service-role client goes around both, so the `eq` on `user_id` is the
only thing left — and its value came from the cookie. The scanner draws the same line: it reports the
unverified session only where the identity scopes a privileged query or decides a role gate.

Seed for the security test: one order per user, `FIXTURE_SEED_JSON` carrying each user's id and the
item name of their single order.
