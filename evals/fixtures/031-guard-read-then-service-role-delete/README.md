# Fixture 031: ownership checked by a guard read, then a service-role delete by bare id

Multi-tenant flow builder (the wacrm shape from the 12 September 2026 real-world run). Deleting a
flow has to bypass an RLS policy that is stricter than the app wants for this action, so the delete
goes through the service-role client and is filtered by `id` only. Whether that is safe depends
entirely on what happened before it.

- `vulnerable/`: `DELETE /api/flows/[id]` authenticates the caller with the cookie client, then
  deletes through the **admin** client filtered by `id`. Any signed-in user deletes any tenant's flow.
- `secure/`: the same delete, preceded by `requireOwnership(id)`: a read of `flows` by the same id
  through the **cookie** client (RLS scopes it to the caller's tenant), and a 404 return when no row
  comes back. The delete itself is unchanged.
- `supabase/`: shared schema and RLS policies (`tenants`, `profiles`, `flows`).

What the scanner must do: flag the vulnerable route with
`supabase.service-role-object-access-without-tenant-scope`, and in the secure twin recognise the
earlier read as the ownership check: same table, same id value (across the helper call), RLS in
force for the read (user-scoped client, select policies scoped to the caller), and a missing row
that stops the entry point. A guard that lacks any of these keeps the finding and is named in the
evidence instead ("could be an ownership check, but ..."): a guard read through the service role,
or one whose missing row is ignored, proves nothing.

Ground truth in `ground-truth.json`, the expected finding in `expected-finding.json`.
