# Fixture 022: tenant id from a hand-rolled request validator

`POST /api/invoices` is a "search" endpoint: instead of a `?tenant=` query parameter (fixture 004),
the caller posts filter criteria as JSON, and the route validates the body with a small hand-written
parser (no zod, no schema library — just the shape-check AI tools write when nothing is installed
yet). Validating that `tenantId` is a non-empty string is not the same as authorizing which tenant
the caller may query.

- `vulnerable/`: `parseInvoiceSearch(body).tenantId` drives `.eq("tenant_id", ...)` against the
  service-role client. Alice posts Tenant B's id and gets Tenant B's invoices.
- `secure/`: the body is still validated (for shape), but the tenant id used to scope the query
  comes from the caller's own `profiles` row, never from the request.
- `supabase/`: shared schema and RLS policies (same shape as fixture 001/009: `tenants`, `profiles`,
  `invoices`).

What the scanner must do: recognize that the return value of a local, non-Supabase helper function
(`parseInvoiceSearch`) is still tainted when it is built from a tainted argument (`body`), and follow
that taint through the property access (`query.tenantId`) into the query filter — the same
"validated but not authorized" mistake as fixture 004, one layer of indirection deeper.

Ground truth in `ground-truth.json`, the expected finding in `expected-finding.json`.
