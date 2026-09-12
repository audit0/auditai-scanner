# 037-policy-trusts-user-metadata

The whole difference is the claim the admin policy trusts. `user_metadata` is written by the user
(`supabase.auth.updateUser({ data })`) and copied into the next access token without review, so the
vulnerable policy grants itself. `app_metadata` can only be written with the service role.

Supabase's own database linter reports the same shape (0015, "rls_references_user_metadata").
