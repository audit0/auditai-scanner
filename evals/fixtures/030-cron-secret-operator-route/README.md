# Fixture 030: cron route guarded by a shared secret, not by a user session

Background job endpoint of a multi-tenant app: `POST /api/cron/purge` deletes expired `jobs` rows
across every tenant through the service-role client. There is no user to authenticate; the caller is
the scheduler (Vercel Cron, GitHub Actions, an external pinger), and the only right way to gate it is
a shared secret the scheduler sends.

- `vulnerable/`: the route performs the privileged delete with no check at all. Anyone who finds the
  URL can trigger it.
- `secure/`: the route compares the `Authorization` header with `process.env.CRON_SECRET` and returns
  401 before touching the database. No `auth.getUser()`, no session: the comparison is the
  authentication.
- `supabase/`: shared schema and RLS policies (`tenants`, `profiles`, `jobs`).

What the scanner must do: flag the vulnerable route with
`supabase.service-role-query-without-authentication`, and recognise the secret comparison in the
secure twin as authentication (kind `secret`) instead of insisting on a Supabase session. The
12 September 2026 real-world run found this shape in PriceAI (`requireAdminOrCronRequest`), wacrm
(`x-cron-secret` with `timingSafeEqual`) and several webhook handlers; every one was a false
positive before this fixture. Evidence-based: a helper merely named `requireAuth` still proves
nothing (see `packages/parser/src/auth-evidence.ts`).

Ground truth in `ground-truth.json`, the expected finding in `expected-finding.json`.
