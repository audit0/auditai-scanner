# Fixture 035: a row id that comes from the caller's credential, not from the request

Public API of a multi-tenant app authenticated by per-tenant API keys (the wacrm shape from the
13 September 2026 real-world run). There is no Supabase session, so every query runs through the
service-role client; `requireApiKey(request)` hashes the bearer token, looks the key row up by
`key_hash` (the authentication), and hands back the tenant and key ids of that row.

- `vulnerable/`: `GET /api/v1/me?key=<id>` reads the key row to describe, and the row it stamps as
  used, from the query string. A caller holding any valid key reads and touches any other tenant's
  key row.
- `secure/`: the route describes `ctx.keyId`, the row the credential resolved to; `touchLastUsed`
  runs inside `requireApiKey` on that same row. Nothing the caller sends chooses a row.
- `supabase/`: shared schema and RLS policies (`tenants`, `profiles`, `api_keys`).

What the scanner must do: flag the vulnerable route with
`supabase.service-role-object-access-without-tenant-scope` (the id is user-controlled), and stay
silent on the secure twin even though `requireApiKey(request)` is a helper handed the request: the
parser follows what the helper returns. A value is untainted when every source of it is identity
or the rows of a query (`const row = await findActiveKeyByHash(hashApiKey(presented))`), so
`row.id`, `row.tenant_id` and the object built from them are not request input, while a helper that
returns its parameter, a property of it, or an object carrying it stays tainted. Before this fixture
the same shape produced 16 false positives in one repository (`touchLastUsed(row.id)` on every
public-API route) plus 6 on `ctx.accountId`, and 12 more on ids of rows the request itself had just
created (PriceAI `createOfferFeedback` and its `after()` callbacks).

Ground truth in `ground-truth.json`, the expected finding in `expected-finding.json`.
