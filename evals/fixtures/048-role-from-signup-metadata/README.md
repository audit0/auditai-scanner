# Fixture 048: role copied from sign-up metadata

`public.user_roles.role` decides who is an admin: the operator console `GET /api/admin/users` checks
it, and `public.is_admin()` opens every tenant's profiles and invoices. Nobody can edit it through
the API. It is written once, at sign-up, by `public.handle_new_user()` (trigger
`on_auth_user_created` on `auth.users`).

The vulnerable function takes the role from `new.raw_user_meta_data ->> 'role'`. That metadata is
whatever the client passes in `supabase.auth.signUp({ options: { data } })`, so anyone who signs up
with `{ role: 'admin' }` is created as an admin: severity critical.

- `vulnerable/supabase/migrations`: `coalesce(new.raw_user_meta_data ->> 'role', 'member')`.
- `secure/supabase/migrations`: `case when ... in ('member', 'viewer') then ... else 'member' end`.
- The route handler and `lib/` are identical in both variants.
- `security-test/`: a new sign-up without metadata is a member (ALLOW), a sign-up asking for admin is
  not an admin (DENY), and that account is refused by the admin route (DENY).

What the scanner must do: find the sign-up trigger, see the column filled unchanged from metadata,
see that the column decides a privilege (the route's role check and `is_admin()`), and stay silent
when the value is chosen from an allow-list.

Status: detected; sandbox pending.
