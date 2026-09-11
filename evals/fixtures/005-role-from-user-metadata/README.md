# Fixture 005: role check reads `user_metadata`

The admin endpoint checks `user.user_metadata.role === "admin"`. In Supabase, `user_metadata` is writable by the signed-in user through `supabase.auth.updateUser({ data: { role: "admin" } })`, so any member promotes themselves. Roles belong in `app_metadata` (service-role only) or in a server-controlled `profiles.role` column.

- `vulnerable/`: `user_metadata.role`.
- `secure/`: `app_metadata.role`.
