# Fixture 034: a table declared public in audit.config.json (ADR-002)

A public price catalogue served through the service role (the PriceAI shape from the 13 September
2026 real-world labels: 37 findings in one repository, every one a public page). RLS is on with no
policies, so the anon key cannot read the table directly; the application decides what is public,
and says so in `audit.config.json`:

```json
{ "publicTables": ["products"] }
```

- Both variants: `GET /api/products` reads the catalogue with the service role and no
  authentication. `supabase.service-role-query-without-authentication` fires, and the declaration
  turns it into `suppressed` with the reason "declared public in audit.config.json". The
  suppression is visible in the report: the summary lists the declared tables and how many
  read-only findings they silenced.
- `vulnerable/`: `POST /api/products` inserts into the same table with no authentication. The
  declaration never covers insert, update, delete or rpc paths (public to read is not public to
  write), so the finding stays critical.
- `secure/`: the write requires a session whose `app_metadata.role` is `admin`.
- `supabase/`: shared schema.

What the scanner must do: suppress only the read-only finding, keep the write, list the declaration
in the summary, and treat `audit.config.json` as untrusted input (validated names, malformed entries
dropped with a warning). Without a declaration, the same read on a table whose own RLS has a
`for select using (true)` policy is lowered to medium with the policy cited (unit tests in
`packages/rules/src/packs/precision.test.ts`), never suppressed: the repository may not have
intended that policy.

Ground truth in `ground-truth.json`, the expected finding in `expected-finding.json`.
