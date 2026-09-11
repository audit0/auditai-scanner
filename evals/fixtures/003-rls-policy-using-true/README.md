# Fixture 003: RLS policy `using (true)`

RLS is enabled and the app uses a per-request client, so everything looks right. But the select policy on `invoices` is `using (true)`: it only checks that the caller is signed in, never which tenant they belong to. Every authenticated user can read every invoice. This is the most common RLS mistake in AI-generated migrations ("allow authenticated users to read").

- `vulnerable/supabase/migrations`: `using (true)`.
- `secure/supabase/migrations`: `using (tenant_id = public.current_tenant_id())`.
