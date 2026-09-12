# 038-policies-without-rls-enabled

`pages` carries four policies and no `enable row level security`, so none of them run. This is the
shape Supabase's linter reports as 0007 (`policy_exists_rls_disabled`): the policies prove the table
was meant to be private, which is what separates it from a table nobody ever protected.

The secure twin differs by exactly one statement.
