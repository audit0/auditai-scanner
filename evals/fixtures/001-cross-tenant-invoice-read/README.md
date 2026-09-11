# Fixture 001: cross-tenant invoice read (IDOR via service-role client)

Minimal multi-tenant invoicing SaaS in the shape AI coding tools produce: Next.js App Router + Supabase.

- `vulnerable/`: the route handler reads the invoice with the **service-role** client and filters by `id` only. RLS is enabled and correct, but the service role bypasses it, so Alice (tenant A) can read Bob's invoice (tenant B).
- `secure/`: the handler uses a per-request client carrying the caller's JWT (RLS applies) and additionally scopes the query by the caller's `tenant_id`.
- `supabase/`: shared schema, RLS policies.
- `seed/`: two tenants, two users, one invoice each.
- `security-test/`: the regression test Audit AI is expected to generate. Fails on `vulnerable`, passes on `secure`.

Ground truth in `ground-truth.json`, the expected finding in `expected-finding.json`.
