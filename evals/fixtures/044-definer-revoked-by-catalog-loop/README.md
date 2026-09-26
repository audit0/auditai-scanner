# 044-definer-revoked-by-catalog-loop

A common hardening migration revokes EXECUTE on every SECURITY DEFINER function of the public schema
with a loop over `pg_proc`. The loop only reaches the functions that exist when it runs.

- **secure**: `find_profile_by_email` is created in 0001, the loop runs in 0002, so the function is
  callable only by the service role and the scanner reports nothing.
- **vulnerable**: the same function is added in 0003, after the loop. It keeps Supabase's default
  EXECUTE for `anon` and `authenticated`, so anyone with the public key reads another person's phone
  number past the owner-only policy on `profiles`.

The scanner follows the loop only in its exact shape (signature select list, `pg_proc` and
`pg_namespace` only, a literal schema and `prosecdef`, a body of GRANT/REVOKE statements, no IF and no
exception handler); any other shape leaves the default grants in place.
