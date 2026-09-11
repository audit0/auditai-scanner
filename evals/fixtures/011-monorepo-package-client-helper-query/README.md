# Fixture 011: monorepo, client from a workspace package, query in a helper package

The shape Makerkit-style kits produce: a `packages/supabase` workspace package exposes client
factories through a package.json `exports` map, a `packages/invoices` package holds the data
access, and the route handler in `apps/web` only wires them together.

- `vulnerable/`: the handler authenticates the caller with the user-scoped client, then calls
  `loadInvoice(getSupabaseServerAdminClient(), id)`. The admin client bypasses RLS and the helper
  filters by `id` only, so Alice reads Bob's invoice.
- `secure/`: the handler passes its own user-scoped client and the caller's `tenant_id` into the
  helper, which adds `.eq("tenant_id", tenantId)`.
- `supabase/`: shared schema with correct RLS.

What the scanner must do: resolve `@kit/supabase/server-admin-client` through the package
`exports` map, resolve `~/lib/http` through tsconfig `paths`, classify `getServiceRoleKey()` as a
service-role key, follow the call into `loadInvoice` with the client and the tainted `id` bound to
its parameters, and attribute the query to `GET /api/invoices/[id]`.

Scan-only fixture: the monorepo layout is not runnable in the sandbox harness yet.
