# auditai-scan

Deterministic security scanner for Next.js (App Router) + Supabase apps. Finds the bugs AI coding
tools ship most: cross-tenant reads, missing or permissive RLS, service-role misuse, unauthenticated
admin routes and server actions, mass assignment, roles read from user-editable metadata.

```bash
npx auditai-scan .                      # scan the current repo
npx auditai-scan . --migrations supabase/migrations --fail-on likely   # CI gate
```

No account, no model call, no network. Source, rules and the eval corpus:
https://github.com/audit0/auditai-scanner. The hosted product that reproduces, fixes and proves
findings in a sandbox lives at https://auditai.sh.
