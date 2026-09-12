# Fixture 019: `@supabase/ssr` cookie auth, project read via a service-role admin client

Minimal multi-tenant project-management SaaS, the `@supabase/ssr` shape AI coding tools produce for
the App Router: a cookie-based client in `lib/supabase/server.ts` (`createServerClient` + `cookies()`)
handles the session, and a separate `lib/supabase/admin.ts` exports a service-role client "for when
you need more than RLS allows".

- `vulnerable/`: the route authenticates the caller with the cookie client's `auth.getUser()`, then
  reads the project with the **admin** client filtered by `id` only. RLS is enabled and correct, but
  the service role bypasses it, so any signed-in user can read any tenant's project by guessing or
  enumerating its id.
- `secure/`: the same route reads with the cookie client itself (RLS applies) and additionally scopes
  the query by the caller's `tenant_id` looked up from `profiles`.
- `supabase/`: shared schema and RLS policies (`tenants`, `profiles`, `projects`).

This is the same defect class as fixture 001 (cross-tenant read via a service-role client without
tenant scope), through the `@supabase/ssr` cookie-client shape and a two-file `lib/supabase/{server,admin}.ts`
split instead of a single bearer-token helper. What the scanner must do: classify
`createServerClient()` as `user_scoped` regardless of which client is used for authentication, and
independently classify `createClient()` with `SUPABASE_SERVICE_ROLE_KEY` in `admin.ts` as
`service_role`, then flag the query that reads through the admin client.

Ground truth in `ground-truth.json`, the expected finding in `expected-finding.json`.
