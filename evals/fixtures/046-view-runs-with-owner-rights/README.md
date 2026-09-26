# 046-view-runs-with-owner-rights

`invoice_totals` is a view over `invoices`, a table whose policy keeps tenants apart. Created without
`security_invoker`, the view runs with its owner's rights, and on Supabase the owner is postgres,
whom row level security does not bind: every tenant's total is readable through the view by anyone
the grants let select it, and the default grants let both API roles. Supabase's linter reports the
shape as 0010 (`security_definer_view`).

The secure twin differs by one clause: `with (security_invoker = on)`.
