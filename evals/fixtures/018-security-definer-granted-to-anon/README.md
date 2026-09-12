# Fixture 018: SECURITY DEFINER function granted to anon

The tenant dashboard asks `public.tenant_invoice_totals(p_tenant_id)` for an invoice count and total.
The function is `SECURITY DEFINER`, so the invoice policies do not apply inside it; it takes the
tenant from its argument and never asks who is calling; and the migration grants EXECUTE to `anon`
(Supabase grants it by default too, unless revoked). Anyone holding the public anon key reads any
tenant's totals at `POST /rest/v1/rpc/tenant_invoice_totals`, no account needed: severity critical
(compare fixture 017, where only signed-in users can call the function).

- `vulnerable/supabase/migrations`: `security definer` and `grant execute ... to anon, authenticated`.
- `secure/supabase/migrations`: `security invoker` (the invoice policies decide what it counts), and
  `revoke execute ... from public, anon` with EXECUTE for `authenticated` only.
- The route handler and `lib/` are identical in both variants.
- `security-test/`: own totals through the app (ALLOW), Bob's totals as Alice (DENY: zero or 404), and
  an anonymous call straight to the RPC endpoint (DENY).

What the scanner must do: apply GRANT/REVOKE on top of Supabase's default EXECUTE privileges, rate
the finding critical because anon can execute the function, and stay silent on the SECURITY INVOKER
version.

Status: detected; sandbox pending.
