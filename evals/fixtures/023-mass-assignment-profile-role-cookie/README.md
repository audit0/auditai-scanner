# Fixture 023: mass assignment survives correct RLS

A variant of fixture 008 through the `@supabase/ssr` cookie-client shape, to make one point
explicit: Row Level Security restricts *rows*, not *columns*. The update policy on `profiles`
(`using (id = auth.uid())`) is correct and the query in `vulnerable/` really is scoped to the
caller's own row — but the whole JSON body is still written as the update payload, so the caller
can set `role` (and, on a differently-shaped table, `tenant_id` or any other column) on their own
row.

- `vulnerable/`: `supabase.from("profiles").update(body).eq("id", user.id)` with the cookie client.
  `{ "display_name": "x", "role": "admin" }` promotes the caller to admin on their own, correctly
  scoped, row.
- `secure/`: explicit allow-list — only `display_name` is copied out of the body.
- `supabase/`: `tenants`, `profiles` with a `role` column and a correct `update own` RLS policy.

What the scanner must do: fire `mass-assignment-from-request-body` regardless of client kind — the
rule already does not require a service-role/bypass client, which is intentional, since mass
assignment is a defect independent of RLS. This fixture pins that behavior down.

Ground truth in `ground-truth.json`, the expected finding in `expected-finding.json`.
