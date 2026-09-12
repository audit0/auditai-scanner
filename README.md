<p align="center">
  <a href="https://auditai.sh"><img src="https://img.shields.io/badge/auditai.sh-product-22c55e?style=flat-square" alt="auditai.sh"></a>
  <a href="https://github.com/audit0/auditai-scanner/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/audit0/auditai-scanner/ci.yml?branch=main&style=flat-square&label=ci" alt="CI"></a>
  <a href="https://www.npmjs.com/package/auditai-scan"><img src="https://img.shields.io/npm/v/auditai-scan?style=flat-square&label=npm" alt="npm"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="Apache-2.0"></a>
  <a href="https://x.com/Audit_AI"><img src="https://img.shields.io/badge/X-%40Audit__AI-000?style=flat-square" alt="X"></a>
</p>

<h1 align="center">Audit AI Scanner</h1>

<p align="center"><strong>Your AI writes code. This scanner finds the bug it ships most: one customer reading another customer's data.</strong></p>

<p align="center">Deterministic security scanner for Next.js (App Router) + Supabase apps. No account, no model, no network. Seconds.</p>

```bash
npx auditai-scan .
```

<p align="center"><img src="./demo.gif" alt="auditai-scan finding a cross-tenant read in a fixture app" width="900"></p>

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

Rule packs `supabase-authorization` and `supabase-storage-rpc`. Every rule ships with a vulnerable
fixture that must fire and a secure fixture that must stay silent.

| Rule | Severity | What it catches |
|---|---|---|
| `supabase.service-role-object-access-without-tenant-scope` | critical | Service-role client, or a direct Drizzle/Prisma connection, reads or writes a row by user-supplied id without tenant scope (IDOR / BOLA) |
| `supabase.user-controlled-tenant-scope` | critical | Tenant scope comes from the request (body, query, params) instead of the session |
| `supabase.service-role-query-without-authentication` | critical | Route or server action queries with the service role and never checks the caller |
| `supabase.service-role-key-exposed-to-client` | critical | Service-role key reaches the browser (`NEXT_PUBLIC_*`, client components). Blocking. |
| `supabase.table-without-rls` | high | Table queried by a user-facing client has row level security disabled |
| `supabase.rls-policy-without-caller-predicate` | high | RLS policy grants rows without referencing the caller (`using (true)` and friends) |
| `supabase.mass-assignment-from-request-body` | high | Request body written to a table without an allow-list |
| `supabase.role-check-from-user-metadata` | high | Authorization decided by `user_metadata`, which the user can edit |
| `supabase.storage-object-access-without-owner-scope` | critical | Storage download/upload/signed URL/move/remove through the service role on a caller-supplied path that is never tied to the caller's user id |
| `supabase.storage-policy-without-owner-check` | high | Policy on `storage.objects` that only checks `bucket_id`: every user reads, overwrites or deletes every file in the bucket |
| `supabase.security-definer-function-without-caller-check` | high, critical if anon can execute | `SECURITY DEFINER` function (RLS skipped inside) that never reads `auth.uid()`, callable through `supabase.rpc()` |
| `supabase.rls-policy-trusts-user-metadata` | critical | RLS policy decides access from a `user_metadata` claim, which the user writes themselves with `updateUser({ data })` |
| `supabase.policies-without-rls-enabled` | high | A table carries policies and never got `enable row level security`, so none of them apply |
| `supabase.anon-write-policy` | high, medium when insert-only | Insert/update/delete policy open to `anon` (or no `TO` clause) whose predicate is `true` |

Findings are reported as `likely`, never `confirmed`: confirmation needs evidence, and evidence
means a reproduced request. Suppressed findings stay in the output, marked `suppressed`.

## What it does not do

- It does not prove the absence of vulnerabilities. Every run ends with an honest coverage line:
  `Checked N risks in class authorization/RLS. Verified: X. Confirmed: Y. Unverified: Z.`
- It does not cover other stacks. Next.js + TypeScript with Supabase clients, Drizzle or Prisma on Postgres; deep rather than wide.
- It does not fix, test or verify. That is the hosted product.
- It does not call a model. Everything here is static analysis on the TypeScript compiler API.

## Usage

```bash
npx auditai-scan [path] [--json] [--fail-on <status>] [--migrations <dir>]...

--json               machine-readable output
--fail-on <status>   exit 1 when a finding reaches this status (default: confirmed)
                     one of: candidate, likely, confirmed, verified
--migrations <dir>   extra directory with Supabase migration SQL (repeatable)

Exit code: 0 clean, 1 a finding reached --fail-on, 2 usage error or <path> is not a directory
```

Project config in `audit.config.json` at the scanned root:

```json
{
  "ignore": ["evals/**"],
  "migrations": ["supabase/migrations"],
  "publicTables": ["products"]
}
```

`publicTables` names tables that are public by design (a catalogue, a blog). A service-role read of
such a table is still listed, as `suppressed` with the declaration printed next to it, so the choice
stays visible in every report; writes to the table are never covered by the declaration.

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

- **parser** maps App Router route handlers, server actions (wrapped ones too) and dynamic pages,
  classifies every Supabase client (`service_role`, `anon`, `user_scoped`) and every Drizzle or
  Prisma connection (`direct_db`: RLS never runs for it), follows calls from the
  entry point into helpers, service classes and workspace packages (tsconfig `paths`, package.json
  `exports`) three levels deep, tracks which arguments carry user input, reads insert/update
  payloads, and ingests RLS policies from migration SQL.
- **graph** links handlers, queries, clients, tables and policies into one structure a rule can walk.
- **rules** are small pure functions over the graph. Each returns findings with file, line, entry
  point, evidence and a one-line remediation.
- **scanner** is the facade and the CLI.

Repository content under analysis is untrusted data. A comment saying "ignore previous
instructions" is just a comment.

## Eval corpus

Thirty-nine fixture pairs today, growing with every rule. The vulnerable app must fire exactly the expected
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
| 011 | monorepo-package-client-helper-query | service-role-object-access-without-tenant-scope, through a workspace package and a helper |
| 012 | wrapped-action-module-client-helper | service-role-object-access-without-tenant-scope, wrapped action and module-level client |
| 013 | drizzle-direct-db-invoice-read | service-role-object-access-without-tenant-scope, Drizzle direct connection |
| 014 | prisma-direct-db-invoice-read | service-role-object-access-without-tenant-scope, Prisma direct connection |
| 015 | storage-download-user-supplied-path | storage-object-access-without-owner-scope |
| 016 | storage-policy-bucket-only | storage-policy-without-owner-check |
| 017 | security-definer-rpc-without-caller-check | security-definer-function-without-caller-check, called via `supabase.rpc()` |
| 018 | security-definer-granted-to-anon | security-definer-function-without-caller-check, executable by anon (critical) |
| 019 | ssr-cookie-admin-project-read | service-role-object-access-without-tenant-scope, `@supabase/ssr` cookie auth + a separate admin client |
| 020 | formdata-server-action-delete | service-role-object-access-without-tenant-scope, id read with `formData.get()` into a local const |
| 021 | dynamic-page-admin-project-read | service-role-object-access-without-tenant-scope, a server-rendered dynamic page as the entry point |
| 022 | hand-rolled-validator-tenant-scope | user-controlled-tenant-scope, tenant id through a hand-written (no-zod) request validator |
| 023 | mass-assignment-profile-role-cookie | mass-assignment-from-request-body, survives a correct RLS update policy |
| 024 | drizzle-task-update-without-org-scope | service-role-object-access-without-tenant-scope, Drizzle direct connection, write path |
| 025 | prisma-delete-note-without-owner-scope | service-role-object-access-without-tenant-scope, Prisma direct connection, server action |
| 026 | rls-policy-missing-owner-predicate | rls-policy-without-caller-predicate, role-only predicate |
| 027 | documents-table-without-rls | table-without-rls |
| 028 | admin-users-list-role-from-user-metadata | role-check-from-user-metadata |
| 029 | rls-policy-member-helper | rls-policy-without-caller-predicate, policy scoped through a helper function |
| 030 | cron-secret-operator-route | service-role-query-without-authentication, secure twin gated by a cron secret instead of a session |
| 031 | guard-read-then-service-role-delete | service-role-object-access-without-tenant-scope, secure twin checks ownership with an RLS-scoped guard read |
| 032 | mass-assignment-map-spread-messages | mass-assignment-from-request-body, `.map()` spread of request rows vs explicit fields |
| 033 | do-block-rls-literal-loop | table-without-rls, RLS switched on in a `DO $$ foreach ... loop execute format(...)` block over a literal list |
| 034 | public-table-declaration | service-role-query-without-authentication, read of a table declared in `audit.config.json` `publicTables` is suppressed (visibly), the write path is not |
| 035 | identity-derived-row-id | service-role-object-access-without-tenant-scope, a row id from the caller's own credential lookup vs one from the query string |
| 036 | ownership-guard-shapes | service-role-object-access-without-tenant-scope, ownership via the parent row, a comparison in code, or a conditional owner filter |
| 037 | policy-trusts-user-metadata | rls-policy-trusts-user-metadata, the admin claim read from `user_metadata` vs `app_metadata` |
| 038 | policies-without-rls-enabled | policies-without-rls-enabled, four policies on a table whose RLS was never switched on |
| 039 | anon-write-policy | anon-write-policy, an open delete policy for `anon` next to a deliberate public insert |

The last three rules read the migrations only: they need no query from your application, because
PostgREST exposes the schema to anyone holding the public key. Their findings name the Data API
as the entry point instead of a route.

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

- More of the authorization family: realtime channels.
- Rules as data with positive and negative fixtures declared next to them.
- Better inter-procedural resolution (helpers that wrap `createClient`, shared query builders).

Wider language and framework support is out of scope until this stack is covered deeply.

## License

Apache-2.0. Built in public by [audit0](https://github.com/audit0). Product: [auditai.sh](https://auditai.sh).
