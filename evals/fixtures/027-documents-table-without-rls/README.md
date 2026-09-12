# Fixture 027: RLS disabled on documents

The app is written correctly: a per-request client carrying the caller's JWT, no service role
anywhere. The bug is in the database: the migration enables RLS on `profiles` but never on
`documents` (the "TODO before launch" that never happened). Any signed-in user, or anyone with
the public anon key, reads every document through PostgREST.

- `vulnerable/supabase/migrations`: no `enable row level security` on documents.
- `secure/supabase/migrations`: RLS enabled with an owner-scoped policy.

The app code (`app/api/documents/[id]/route.ts`, `lib/supabase.ts`) is identical in both
variants; only the migration changes, so migrations live inside each variant.
