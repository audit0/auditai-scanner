<p align="center">
  <a href="https://auditai.sh"><img src="./.github/assets/banner.png" alt="Audit AI. Your AI writes code. We prove it's safe to merge. Open-source security scanner for Next.js + Supabase apps: npx auditai-scan ." width="100%"></a>
</p>

<p align="center">
  <a href="https://auditai.sh"><img src="https://img.shields.io/badge/auditai.sh-product-22c55e?style=flat-square" alt="auditai.sh"></a>
  <a href="https://github.com/audit0/auditai-scanner/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/audit0/auditai-scanner/ci.yml?branch=main&style=flat-square&label=ci" alt="CI"></a>
  <a href="https://www.npmjs.com/package/auditai-scan"><img src="https://img.shields.io/npm/v/auditai-scan?style=flat-square&label=npm" alt="npm"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="Apache-2.0"></a>
  <a href="https://x.com/Audit_AI"><img src="https://img.shields.io/badge/X-%40Audit__AI-000?style=flat-square" alt="X"></a>
</p>

<p align="center">
  <a href="https://auditai.sh">Scan a repository</a> ·
  <a href="https://auditai.sh/r/demo">Sample report</a> ·
  <a href="https://auditai.sh/docs">Docs</a> ·
  <a href="https://auditai.sh/stats">Measured precision</a> ·
  <a href="https://github.com/audit0/auditai-playground">Playground</a> ·
  <a href="https://youtube.com/shorts/_0e0qbXlorI">Video</a>
</p>

<p align="center"><strong>Your AI writes code. This scanner finds the bug it ships most: one customer reading another customer's data.</strong></p>

<p align="center">Deterministic security scanner for Next.js (App Router) + Supabase apps. No account, no model, no network. Seconds.</p>

```bash
npx auditai-scan .
```

<p align="center"><img src="./demo.gif" alt="auditai-scan finding a cross-tenant read in a fixture app" width="900"></p>

```
Audit AI scan  evals/fixtures/001-cross-tenant-invoice-read/vulnerable
Files 6 · Routes 1 · Supabase queries 1 · Tables with RLS 3/3 · Rules 14

AUDIT-001  LIKELY  CRITICAL  Cross-tenant select on "invoices" via service-role client
  Entry   GET /api/invoices/[id]   app/api/invoices/[id]/route.ts:6
  Path    HTTP request -> GET /api/invoices/[id] -> id eq id (user-controlled) -> createServiceRoleClient (service role, bypasses RLS) -> public.invoices.select
  Why     select on public.invoices filtered by user-controlled "id" through a service-role client, with no tenant/owner scoping. The handler authenticates the caller but never checks that the row belongs to them. RLS is enabled on public.invoices with 2 policies, but the service role bypasses it.
  Where   app/api/invoices/[id]/route.ts:6, app/api/invoices/[id]/route.ts:14, lib/supabase.ts:7
  Rule    supabase.service-role-object-access-without-tenant-scope · CWE-639, CWE-284 · confidence 0.85

Checked 1 risk in class authorization/RLS. Verified: 0. Confirmed (no sandbox): 0. Unverified: 0.
```

This is the open-source engine behind [Audit AI](https://auditai.sh). The scanner gives you the
deterministic part: every route, server action, page, Supabase client, query, RLS policy and
database function, mapped and checked. The hosted product takes a finding from here and tries to
prove it.

## Try the whole loop

54 seconds on the [playground app](https://github.com/audit0/auditai-playground): a scan by link,
the finding in plain words, Prove it in the sandbox, Alice reading Bob's invoice, then the fix
verified by the same attack. The opening message is illustrative and the voice is synthetic;
everything on screen after it is the live product. Also on [YouTube](https://youtube.com/shorts/_0e0qbXlorI).

https://github.com/user-attachments/assets/50ac7fdf-3a84-4089-a106-44ada2a8f081

- **Scan a public repository by link** at [auditai.sh](https://auditai.sh), free and without an
  account. The report explains each finding in plain words for the app's owner and gives the
  developer the code path and a ready task for Cursor or Claude Code. [Sample report](https://auditai.sh/r/demo).
- **Prove it.** A button on the report starts a sandbox run: a local Supabase with your migrations,
  two users seeded from your schema, and a generated test in which Alice asks for Bob's rows. The
  verdict is `Reproduced` only if the attack actually works. When the fix is a migration, the
  sandbox applies it and runs the same attack again; `Verified fix` needs every `DENY` test to pass
  and every `ALLOW` test to stay green. A person approves each sandbox run on a repository we have
  not seen before.
- **A check on every pull request** with the [GitHub App](https://github.com/apps/auditai-sh).
- **A deliberately vulnerable app to try it on:** [audit0/auditai-playground](https://github.com/audit0/auditai-playground).
  It has three holes of three kinds (a service-role read by id, a table without RLS, a
  `SECURITY DEFINER` function), and all three are proven on the live product.

## Why this exists

Lovable, Bolt, v0, Cursor and Claude Code generate the same shape of app: Next.js App Router,
Supabase for auth and data, TypeScript. They also make the same class of mistake: a route handler
that uses the service-role key and filters by `id` only, an RLS policy that says `using (true)`, a
tenant id read from the request body, a role read from `user_metadata`. Generic scanners do not see
these because they do not understand the framework. This one does nothing else.

## What it finds

Rule packs `supabase-authorization`, `supabase-storage-rpc` and `supabase-sql-policies`. Every rule
ships with a vulnerable fixture that must fire and a secure fixture that must stay silent.

| Rule | Severity | What it catches |
|---|---|---|
| `supabase.service-role-object-access-without-tenant-scope` | critical | Service-role client, or a direct Drizzle/Prisma connection, reads or writes a row by user-supplied id without tenant scope (IDOR / BOLA) |
| `supabase.user-controlled-tenant-scope` | critical | Tenant scope comes from the request (body, query, params) instead of the session |
| `supabase.service-role-query-without-authentication` | critical | Route or server action queries with the service role and never checks the caller |
| `supabase.service-role-key-exposed-to-client` | critical | Service-role key reaches the browser (`NEXT_PUBLIC_*`, client components). Blocking. |
| `supabase.table-without-rls` | high | Table queried by a user-facing client has row level security disabled |
| `supabase.rls-policy-without-caller-predicate` | high | RLS policy grants rows without referencing the caller (`using (true)` and friends) |
| `supabase.mass-assignment-from-request-body` | high | Request body written to a table without an allow-list, where RLS does not already refuse the write |
| `supabase.role-check-from-user-metadata` | high | Authorization decided by `user_metadata`, which the user can edit |
| `supabase.storage-object-access-without-owner-scope` | critical | Storage download/upload/signed URL/move/remove through the service role on a caller-supplied path that is never tied to the caller's user id |
| `supabase.storage-policy-without-owner-check` | high | Policy on `storage.objects` that only checks `bucket_id`: every user reads, overwrites or deletes every file in the bucket |
| `supabase.security-definer-function-without-caller-check` | high, critical if anon can execute | `SECURITY DEFINER` function (RLS skipped inside) that never reads `auth.uid()`, callable through `supabase.rpc()` |
| `supabase.rls-policy-trusts-user-metadata` | critical | RLS policy decides access from a `user_metadata` claim, which the user writes themselves with `updateUser({ data })` |
| `supabase.policies-without-rls-enabled` | high | A table carries policies and never got `enable row level security`, so none of them apply |
| `supabase.anon-write-policy` | high, medium when insert-only | Insert/update/delete policy open to `anon` (or no `TO` clause) whose predicate is `true` |

Findings are reported as `likely`, never `confirmed`: confirmation needs evidence, and evidence
means a reproduced request. Suppressed findings stay in the output, marked `suppressed`.

The last three rules read the migrations only: they need no query from your application, because
PostgREST exposes the schema to anyone holding the public key. Their findings name the Data API
as the entry point instead of a route.

## Fixes it proposes

Findings whose fix follows from the schema alone come with that fix: one migration, printed under
the finding and included in `--json` as `fix`. No model is involved and nothing is applied: it is
SQL to read and apply yourself.

```
AUDIT-001  LIKELY  HIGH  SECURITY DEFINER function "get_invoice" without a caller check
  Entry   GET /api/invoices/[id], POST /rest/v1/rpc/get_invoice   supabase/migrations/0001_init.sql:55
  ...
  Fix     Run get_invoice with the caller's rights (security invoker) (supabase/migrations/20260913175911_fix_security_invoker_get_invoice.sql)
          -- Run get_invoice with the caller's rights, so row level security applies inside it
          -- Proposed by Audit AI. Read it, then apply it with the rest of your migrations.
          -- It reads public.invoices, and each of them has row level security with policies.
          alter function public.get_invoice(uuid) security invoker;
```

Today that covers the `SECURITY DEFINER`, row-level-security and write-policy rules, about a
quarter of what the scanner reports on real repositories. Every table, function and policy name in
a proposed migration is resolved against the parsed schema. A finding whose fix lives in
application code gets no proposal, on purpose.

## How precise it is

Measured by hand on public repositories the engine had never seen. The selection rule and the
sample size were written down and committed before any repository was picked; the sample was drawn
before any code was read. Precision is real ÷ (real + false positive); findings labeled `unsure` are
left out of the denominator.

| Blind sample | Repositories | Findings labeled | Precision | Blocking tier (high + critical) |
|---|---:|---:|---:|---:|
| 1st, 13 Sep 2026 | 20 | 100 | **36%** (36/100) | 35% (32/92) |
| 2nd, 13 Sep 2026, after precision rounds 4–5 | 20 new | 100 | **46%** (44/95, 95% interval 37–56%) | 49% (43/87) |

- The rise from 36% to 46% is not statistically proven at this sample size (p ≈ 0.14). The honest
  reading: the fixes did not hurt precision on unfamiliar code, and probably raised it.
- Strong in the second sample: open write policies for `anon` (13 of 14 real) and RLS policies that
  trust `user_metadata` (7 of 7). Weak: service-role reads by id (2 of 18) and `SECURITY DEFINER`
  functions (12 of 30), where most false positives were public-by-design functions and an internal
  tool behind a corporate login.
- The engine in this repository carries precision round 6, made with the second sample's labels in
  view, so its numbers on those labels are no longer blind. The next honest number comes from a
  third sample.
- Repository names and labels stay private: a real finding is a real vulnerability in someone's app.

Live numbers, including every sample so far: [auditai.sh/stats](https://auditai.sh/stats). This is
why the hosted product proves before it blocks: a `likely` finding is a lead, not a verdict.

## What it does not do

- It does not prove the absence of vulnerabilities. Every run ends with an honest coverage line:
  `Checked N risks in class authorization/RLS. Verified: X. Confirmed: Y. Unverified: Z.`
- It does not cover other stacks. Next.js + TypeScript with Supabase clients, Drizzle or Prisma on Postgres; deep rather than wide.
- It does not change your code. Schema-level fixes are printed for you to apply; application-code
  fixes, regression tests and sandbox proof are the hosted product.
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

This repository carries its own `audit.config.json` that excludes `evals/**`: the fixtures are
deliberately vulnerable demo apps, so scanning the repository as a project would report them as
findings. The eval gate scans each fixture directly and is not affected by that file.

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
source files ──► parser ──► Program Security Graph ──► rules ──► findings + coverage ──► fixes
                 (TS compiler API)   Route → Handler → Query → Client / Table → RLSPolicy
```

- **parser** maps App Router route handlers, server actions (wrapped ones too) and dynamic pages,
  classifies every Supabase client (`service_role`, `anon`, `user_scoped`) and every Drizzle or
  Prisma connection (`direct_db`: RLS never runs for it), follows calls from the
  entry point into helpers, service classes and workspace packages (tsconfig `paths`, package.json
  `exports`) three levels deep, tracks which arguments carry user input and which values come from
  the caller's own identity, recognises guards (session, credential and secret checks, ownership
  reads, layout gates), and reads tables, columns, policies, grants, functions, triggers and storage
  buckets from migration SQL.
- **graph** links handlers, queries, clients, tables and policies into one structure a rule can walk.
- **rules** are small pure functions over the graph. Each returns findings with file, line, entry
  point, evidence and a one-line remediation.
- **fixes** derives a migration from the schema when the fix needs nothing else.
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

- Precision before breadth: the weakest rules above first, then a third blind sample on the engine
  that ships.
- More of the authorization family: realtime channels.
- Proposed migrations for more of the SQL class.
- Better inter-procedural resolution (helpers that wrap `createClient`, shared query builders).

Wider language and framework support is out of scope until this stack is covered deeply.

## License

Apache-2.0. Built in public by [audit0](https://github.com/audit0). Product: [auditai.sh](https://auditai.sh).
Security reports: security@auditai.sh.
