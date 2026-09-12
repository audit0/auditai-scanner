# Fixture 033: RLS switched on inside a DO block that loops over a literal list

The app is written correctly: a per-request client carrying the caller's JWT, no service role
anywhere. Tenant isolation lives in the database and is applied the way larger schemas do it (the
DeskcommCRM shape from the 13 September 2026 real-world run): one PL/pgSQL block enables RLS,
creates the tenant policy and revokes `anon` for every table in a literal list.

- `vulnerable/supabase/migrations`: the list names `notes_archive` only. `notes` was forgotten when
  the archive table was added, so it has no RLS and any signed-in user (or the anon key) reads
  every note through PostgREST.
- `secure/supabase/migrations`: the list names both tables.

Migrations live inside each variant because the two variants differ only in SQL.

What the scanner must do: unroll `foreach t in array array[...] loop execute format(...) end loop`
over the literal list and feed the expanded `alter table ... enable row level security`,
`create policy ...` and `revoke ...` statements through the normal handlers, so that the secure twin
is seen as protected and the vulnerable one is flagged with `supabase.table-without-rls`. Only
literal lists are followed (`array[...]`, `select unnest(array[...])`, `(values (...), (...))`); a
loop over a query, an EXECUTE built from expressions or one placed under an IF stays dynamic SQL,
and the scan reports one warning naming the file instead of guessing.

Ground truth in `ground-truth.json`, the expected finding in `expected-finding.json`.
