# Fixture 002: RLS disabled on invoices

The app is written correctly: a per-request client carrying the caller's JWT, no service role anywhere. The bug is in the database: the migration enables RLS on `profiles` and `tenants` but never on `invoices` (the "TODO before launch" that never happened). Any signed-in user, or anyone with the public anon key, reads every invoice through PostgREST.

- `vulnerable/supabase/migrations`: no `enable row level security` on invoices.
- `secure/supabase/migrations`: RLS enabled with tenant policies.

Migrations live inside each variant because the two variants differ only in SQL.
