# Fixture 014: Prisma, direct database connection, invoice read by id

The Prisma shape of fixture 001. `lib/prisma.ts` holds the usual
`globalThis.prisma ?? new PrismaClient()` singleton. Prisma connects to Postgres directly, so
Supabase RLS never applies; the scanner classifies the client as `direct_db`.

- `vulnerable/`: `prisma.invoice.findUnique({ where: { id } })` after authenticating the caller.
- `secure/`: `prisma.invoice.findFirst({ where: { id, tenantId: profile.tenantId } })` with the
  tenant taken from the caller's profile.

What the scanner must do: see through the `??` singleton, map the `invoice` accessor to the
`invoices` table through `@@map` in `prisma/schema.prisma`, read the `where` object as filters
(shorthand `{ id }` included), and treat camelCase `tenantId` as the tenant scope column. Scan-only fixture.
