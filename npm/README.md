# auditai-scan

Deterministic security scanner for Next.js (App Router) + Supabase apps. Finds the bugs AI coding
tools ship most: cross-tenant reads, missing or permissive RLS, service-role misuse, unauthenticated
admin routes and server actions, mass assignment, roles read from user-editable metadata.

```bash
npx auditai-scan --snapshot-query          # a read-only query: run it in the Supabase SQL editor
npx auditai-scan --snapshot snapshot.json  # what your live database lets a stranger do
npx auditai-scan .                         # scan the current repo
npx auditai-scan . --migrations supabase/migrations --fail-on likely   # CI gate
```

The snapshot query reads the Postgres catalog (tables, row level security, policies, grants,
functions, storage buckets) and changes nothing; no row of your data is read. Findings about the
database are headlines and come with the migration that closes them. Findings inferred from
application code are printed as leads: about one in four is real on code the rules have never seen,
so they are capped at medium and never fail `--fail-on`.

No account, no model call, no network. Source, rules and the eval corpus:
https://github.com/audit0/auditai-scanner. The hosted product that reproduces, fixes and proves
findings in a sandbox lives at https://auditai.sh.
