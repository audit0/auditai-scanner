# Fixture 026: RLS policy checks the role, not the owner

RLS is enabled and the route uses a proper `@supabase/ssr` cookie client, so everything looks
right at a glance. But the select policy on `projects` is `using (auth.role() = 'authenticated')`:
it only checks that the caller is signed in, never who owns the row. Every authenticated user can
read every other user's project. This reads as correct to a reviewer skimming for `using (true)`
only — the predicate here calls a real `auth.*` function, it just calls the wrong one.

- `vulnerable/supabase/migrations`: `using (auth.role() = 'authenticated')`.
- `secure/supabase/migrations`: `using (owner_id = auth.uid())`.

The app code (`app/api/projects/[id]/route.ts`, `lib/supabase-server.ts`) is identical in both
variants; only the policy predicate changes, so migrations live inside each variant.
