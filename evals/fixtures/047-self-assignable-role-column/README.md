# Fixture 047: self-assignable role column

The operator console `GET /api/admin/users` returns every tenant's users, and the admin policies on
`profiles` and `invoices` go through `public.is_admin()`. Both decide from `profiles.role`.

Users may edit their own profile through the Data API: policy `"profiles: update own"` is
`USING (id = auth.uid())` with no `WITH CHECK`, and the table keeps Supabase's default UPDATE
privilege on every column. So one request with the user's own token,
`PATCH /rest/v1/profiles?id=eq.<me>` with `{ "role": "admin" }`, makes them an admin: severity
critical.

- `vulnerable/supabase/migrations`: the policy as above, default privileges.
- `secure/supabase/migrations`: the same policy, but `revoke update on public.profiles from
  authenticated; grant update (full_name) on public.profiles to authenticated`.
- The route handler and `lib/` are identical in both variants.
- `security-test/`: Alice edits her display name (ALLOW), Alice sets her own role to admin (DENY),
  Alice calls the admin route after that attempt (DENY).

Both variants also have `POST /api/admin/users`, where an admin adds a member to their tenant with the
service role (role always `member`): the way profile rows come to exist, which the rule requires since
27 September 2026.

What the scanner must do: see that `profiles.role` decides a privilege (the route's role check and
`is_admin()`), that the own-row UPDATE policy leaves the column free, and that the table privilege was
not narrowed; stay silent once UPDATE is granted back column by column.

Status: detected; sandbox pending.
