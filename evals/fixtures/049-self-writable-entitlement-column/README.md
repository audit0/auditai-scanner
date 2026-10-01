# Fixture 049: self-writable entitlement column

`POST /api/invoices/export` is a paid export: each call costs one credit. The route refuses with 402
when `profiles.credits` is zero, and `public.spend_export_credit()` takes a credit away. Both decide
from `profiles.credits`.

Users may edit their own profile through the Data API: policy `"profiles: update own"` is
`USING (id = auth.uid())` with no `WITH CHECK`, and the table keeps Supabase's default UPDATE
privilege on every column. So one request with the user's own token,
`PATCH /rest/v1/profiles?id=eq.<me>` with `{ "credits": 1000000 }`, gives them unlimited paid
exports: severity high (money, not another tenant's data).

- `vulnerable/supabase/migrations`: the policy as above, default privileges.
- `secure/supabase/migrations`: the same policy, but `revoke update on public.profiles from
  authenticated; grant update (full_name) on public.profiles to authenticated`. The definer function
  still spends credits, as the table owner.
- The route handler and `lib/` are identical in both variants.
- `security-test/`: Alice edits her display name (ALLOW), Alice sets her own credits (DENY), Alice
  exports after spending her credits (DENY).

What the scanner must do: see that `profiles.credits` is decided on (the route's exit and the definer
function's check), that the own-row UPDATE policy leaves the column free, and that the table privilege
was not narrowed; stay silent once UPDATE is granted back column by column. The shape comes from
hatex-terminal and four more repositories (`docs/realworld/2026-09-27-entitlement-columns-search.md`).

Status: detected; sandbox pending.
