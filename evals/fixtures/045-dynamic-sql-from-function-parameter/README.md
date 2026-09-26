# Fixture 045: dynamic SQL built from a function parameter

The invoice search asks `public.search_invoices(p_customer)`. The function does filter by the caller's
tenant (`public.current_tenant_id()` reads `auth.uid()`), so the SECURITY DEFINER rule (S3) rightly
stays silent. But it builds the statement as a string and glues the search text into it:

```sql
return query execute
  'select * from public.invoices where tenant_id = public.current_tenant_id() and customer_name ilike ''%'
  || p_customer || '%'' order by created_at desc';
```

A search for `%' or true --` closes the literal and comments out the rest, so the tenant filter is
gone. The function is SECURITY DEFINER (the invoice policies do not apply inside it) and anon may
execute it, so anyone with the public anon key reads every tenant's invoices at
`POST /rest/v1/rpc/search_invoices`: severity critical.

- `vulnerable/supabase/migrations`: `security definer`, the value glued in with `||`, EXECUTE for
  `anon, authenticated`.
- `secure/supabase/migrations`: `security invoker`, the value bound with `USING`, EXECUTE revoked from
  public and anon.
- The route handler and `lib/` are identical in both variants.
- `security-test/`: Alice's own search (ALLOW), Alice's injected search (DENY: nothing from Bob's
  tenant), and an anonymous injected call straight to the RPC endpoint (DENY).

What the scanner must do: read the function body, see the text parameter reach the EXECUTE statement
text unquoted, rate it critical because the function is SECURITY DEFINER and anon can execute it, and
stay silent when the value only reaches USING.

Status: detected; sandbox pending.
