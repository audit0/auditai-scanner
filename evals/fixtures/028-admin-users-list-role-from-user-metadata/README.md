# Fixture 028: admin user list gated by `user_metadata`

Same defect class as fixture 005, different blast radius: instead of gating a stats endpoint, the
admin check here gates a full cross-tenant user listing (`profiles.id, email, tenant_id` for
every tenant). The endpoint checks `user.user_metadata.role === "admin"`. In Supabase,
`user_metadata` is writable by the signed-in user through
`supabase.auth.updateUser({ data: { role: "admin" } })`, so any member promotes themselves and
dumps every tenant's user list. Roles belong in `app_metadata` (service-role only) or in a
server-controlled `profiles.role` column.

- `vulnerable/`: `user_metadata.role`.
- `secure/`: `app_metadata.role`.
