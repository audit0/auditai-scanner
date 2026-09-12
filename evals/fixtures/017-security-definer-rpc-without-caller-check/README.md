# Fixture 017: SECURITY DEFINER function without a caller check, called via rpc

The app looks protected: `GET /api/invoices/[id]` uses a per-request client carrying the caller's
JWT, and the invoice policies are correct. But the read goes through
`supabase.rpc("get_invoice", { invoice_id: id })`, and `public.get_invoice()` is `SECURITY DEFINER`:
it runs as its owner, so the invoice policies do not apply inside it, and its body filters by the id
the caller sends without ever asking who the caller is. Any signed-in user reads any invoice, through
the app or straight through `POST /rest/v1/rpc/get_invoice`. EXECUTE is revoked from anon and PUBLIC,
so anonymous visitors are out: severity high, not critical (compare fixture 018).

- `vulnerable/supabase/migrations`: `select * from public.invoices where id = invoice_id`.
- `secure/supabase/migrations`: `... where id = invoice_id and owner_id = auth.uid()`.
- The route handler and `lib/` are identical in both variants.
- `security-test/`: identity matrix through the app plus a direct RPC call as Alice for Bob's invoice.

What the scanner must do: read the function from the migrations (SECURITY DEFINER, no auth.uid()
in the body, executable by authenticated after the GRANT/REVOKE statements), and connect it to the
`supabase.rpc("get_invoice")` call site in the route. The `current_tenant_id()` helper is also
SECURITY DEFINER but reads `auth.uid()`, so it must stay silent.

Status: detected; sandbox pending.
