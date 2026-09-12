# Fixture 029: RLS policy scoped through a membership helper

Real CRM and SaaS repositories rarely write `auth.uid()` into every policy. They call a helper:
`using (public.is_account_member(account_id))`, `organization_id in (select public.fn_user_org_ids())`.
Whether such a policy ties rows to the caller depends on the helper's body, not on the policy text.

- `vulnerable/supabase/migrations`: `is_account_member(p_account_id)` only checks that the account has
  members (`select exists (... where tenant_id = p_account_id)`). Every account passes for everyone,
  so every signed-in user reads every account's notes.
- `secure/supabase/migrations`: the same helper adds `and id = auth.uid()`.
- The route handler and `lib/` are identical in both variants.
- `security-test/`: each user writes a note into their own account with their own session, then asks
  the app for their own and the other account's note.

What the scanner must do: evaluate the policy through the helper. A call to a migration function whose
body reads `auth.uid()`/`auth.jwt()` counts as a caller predicate; an unknown or non-checking helper does
not. The secure policy was a false positive before (fixed for DeskcommCRM- and wacrm-style policies).
The vulnerable helper is also a SECURITY DEFINER function without a caller check, so
`supabase.security-definer-function-without-caller-check` fires there too.

Status: detected; sandbox pending.
