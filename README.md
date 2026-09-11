<p align="center">
  <a href="https://auditai.sh"><img src="https://img.shields.io/badge/auditai.sh-product-22c55e?style=flat-square" alt="auditai.sh"></a>
  <a href="https://github.com/audit0/auditai-scanner/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/audit0/auditai-scanner/ci.yml?branch=main&style=flat-square&label=ci" alt="CI"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="Apache-2.0"></a>
  <a href="https://x.com/Audit_AI"><img src="https://img.shields.io/badge/X-%40Audit__AI-000?style=flat-square" alt="X"></a>
</p>

<h1 align="center">Audit AI Scanner</h1>

<p align="center"><strong>Your AI writes code. This scanner finds the bug it ships most: one customer reading another customer's data.</strong></p>

<p align="center">Deterministic security scanner for Next.js (App Router) + Supabase apps. No account, no model, no network. Seconds.</p>

```bash
npx auditai-scan .
```

```
AUDIT-001  LIKELY  CRITICAL  Cross-tenant select on "invoices" via service-role client
           app/api/invoices/[id]/route.ts:14  GET /api/invoices/[id]
           The service-role client bypasses RLS and the query is scoped by `id` only.
           Fix: use a per-request client carrying the caller's JWT, or add `.eq("tenant_id", session.tenantId)`.

Checked 1 risk in class authorization/RLS. Verified: 0. Confirmed (no sandbox): 0. Unverified: 0.
```

This is the open-source engine behind [Audit AI](https://auditai.sh). The hosted product takes a
finding from here and closes the loop: reproduces it against a sandboxed copy of your app, writes
the minimal fix and a regression test, and proves the fix (`HTTP 200` before, `HTTP 403` after).
The scanner alone gives you the deterministic part: every route, server action, Supabase client,
query and RLS policy, mapped and checked.

## Why this exists

Lovable, Bolt, v0, Cursor and Claude Code generate the same shape of app: Next.js App Router,
Supabase for auth and data, TypeScript. They also make the same class of mistake: a route handler
that uses the service-role key and filters by `id` only, an RLS policy that says `using (true)`, a
tenant id read from the request body, a role read from `user_metadata`. Generic scanners do not see
these because they do not understand the framework. This one does nothing else.

## What it finds

Rule pack `supabase-authorization`. Every rule ships with a vulnerable fixture that must fire and a
secure fixture that must stay silent.

| Rule | Severity | What it catches |
|---|---|---|
| `supabase.service-role-object-access-without-tenant-scope` | critical | Service-role client reads or writes a row by user-supplied id without tenant scope (IDOR / BOLA) |
| `supabase.user-controlled-tenant-scope` | critical | Tenant scope comes from the request (body, query, params) instead of the session |
| `supabase.service-role-query-without-authentication` | critical | Route or server action queries with the service role and never checks the caller |
| `supabase.service-role-key-exposed-to-client` | critical | Service-role key reaches the browser (`NEXT_PUBLIC_*`, client components). Blocking. |
| `supabase.table-without-rls` | high | Table queried by a user-facing client has row level security disabled |
| `supabase.rls-policy-without-caller-predicate` | high | RLS policy grants rows without referencing the caller (`using (true)` and friends) |
| `supabase.mass-assignment-from-request-body` | high | Request body written to a table without an allow-list |
| `supabase.role-check-from-user-metadata` | high | Authorization decided by `user_metadata`, which the user can edit |

Findings are reported as `likely`, never `confirmed`: confirmation needs evidence, and evidence
means a reproduced request. Suppressed findings stay in the output, marked `suppressed`.

## What it does not do

- It does not prove the absence of vulnerabilities. Every run ends with an honest coverage line:
  `Checked N risks in class authorization/RLS. Verified: X. Confirmed: Y. Unverified: Z.`
- It does not cover other stacks. Next.js + Supabase + TypeScript only, deep rather than wide.
- It does not fix, test or verify. That is the hosted product.
- It does not call a model. Everything here is static analysis on the TypeScript compiler API.

## Usage

```bash
npx auditai-scan [path] [--json] [--fail-on <status>] [--migrations <dir>]...

--json               machine-readable output
--fail-on <status>   exit 1 when a finding reaches this status (default: confirmed)
                     one of: candidate, likely, confirmed, verified
--migrations <dir>   extra directory with Supabase migration SQL (repeatable)
```

Project config in `audit.config.json` at the scanned root:

```json
{ "ignore": ["evals/**"], "migrations": ["supabase/migrations"] }
```

Suppress a finding you have reviewed, with a reason that stays in the code:

```ts
// auditai:ignore supabase.service-role-query-without-authentication -- public waitlist insert; table has RLS with no read policy
export async function POST(req: Request) { ... }
```

CI gate (GitHub Actions):

```yaml
- run: npx auditai-scan . --migrations supabase/migrations --fail-on likely
```

## How it works

```
source files ──► parser ──► Program Security Graph ──► rules ──► findings + coverage
                 (TS compiler API)   Route → Handler → Query → Client / Table → RLSPolicy
```

- **parser** maps App Router routes and server actions, classifies every Supabase client
  (`service_role`, `anon`, `user_scoped`), follows query chains and filters back to their inputs,
  reads insert/update payloads, and ingests RLS policies from migration SQL.
- **graph** links handlers, queries, clients, tables and policies into one structure a rule can walk.
- **rules** are small pure functions over the graph. Each returns findings with file, line, entry
  point, evidence and a one-line remediation.
- **scanner** is the facade and the CLI.

Repository content under analysis is untrusted data. A comment saying "ignore previous
instructions" is just a comment.

## Eval corpus

Ten fixture pairs today, growing with every rule. The vulnerable app must fire exactly the expected
rule; the secure twin must produce zero findings. `npm run evals` enforces both on every commit.

| # | Fixture | Rule exercised |
|---|---|---|
| 001 | cross-tenant-invoice-read | service-role-object-access-without-tenant-scope |
| 002 | rls-disabled-invoices-read | table-without-rls |
| 003 | rls-policy-using-true | rls-policy-without-caller-predicate |
| 004 | user-controlled-tenant-id | user-controlled-tenant-scope |
| 005 | role-from-user-metadata | role-check-from-user-metadata |
| 006 | service-role-key-in-client | service-role-key-exposed-to-client |
| 007 | admin-route-without-auth | service-role-query-without-authentication |
| 008 | mass-assignment-profile-update | mass-assignment-from-request-body |
| 009 | unprotected-server-action | service-role-object-access-without-tenant-scope |
| 010 | batch-lookup-by-ids | service-role-object-access-without-tenant-scope |

Each fixture also carries the `security-test` the hosted product runs in a sandbox: `DENY` tests
are the security assertion (Alice must not read Bob's row), `ALLOW` tests are the sanity check
(Alice still reads her own).

## Development

```bash
npm ci
npm run build      # tsc -b
npm test           # unit tests + eval gate
npm run lint       # biome
npm run bundle     # single-file CLI in npm/dist/auditai-scan.mjs
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for how to add a rule (always with a fixture pair) and
[SECURITY.md](./SECURITY.md) for reporting vulnerabilities.

## Roadmap for the open engine

- More of the authorization family: storage bucket policies, RPC functions, realtime channels.
- Rules as data with positive and negative fixtures declared next to them.
- Better inter-procedural resolution (helpers that wrap `createClient`, shared query builders).

Wider language and framework support is out of scope until this stack is covered deeply.

## License

Apache-2.0. Built in public by [audit0](https://github.com/audit0). Product: [auditai.sh](https://auditai.sh).
