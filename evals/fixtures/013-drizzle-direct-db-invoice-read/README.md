# Fixture 013: Drizzle, direct database connection, invoice read by id

The Drizzle shape of fixture 001. `lib/db.ts` opens a direct Postgres connection with
`drizzle(postgres(DATABASE_URL))`; nothing goes through PostgREST, so the RLS policy in
`drizzle/0000_init.sql` never runs for these queries. The scanner classifies the client as
`direct_db` and treats it like the service role.

- `vulnerable/`: `db.select().from(invoices).where(eq(invoices.id, id))` after authenticating the
  caller. Any signed-in user reads any invoice.
- `secure/`: the caller's `tenantId` comes from `db.query.profiles.findFirst(...)` by `user.id`
  and the invoice query adds `eq(invoices.tenantId, profile.tenantId)`.

What the scanner must do: resolve `invoices` to the table name through the `pgTable` declaration,
read `eq(...)`/`and(...)` predicates as filters, classify `db` as a direct connection, and not
flag the profile lookup (identity, not user input). Scan-only fixture.
