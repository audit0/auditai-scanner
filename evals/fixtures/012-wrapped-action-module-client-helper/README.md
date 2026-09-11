# Fixture 012: wrapped server action, module-level admin client, helper in lib/

Three habits of AI-generated code in one fixture:

1. the server action is wrapped (`export const deleteInvoice = enhanceAction(async (data) => ...)`)
   so the handler is the first argument of a call, not an exported function;
2. the admin client is a module-level constant (`export const supabaseAdmin = createClient(...)`)
   imported wherever it is needed;
3. the query lives in a helper (`removeInvoice(id)` in `lib/invoices.ts`), not in the action.

- `vulnerable/`: the wrapper authenticates the caller, the action forwards `data.id` to
  `removeInvoice`, which deletes by `id` through the service-role client. Bob deletes Alice's invoice.
- `secure/`: the tenant id comes from the authenticated user's `app_metadata` (server-controlled)
  and the helper adds `.eq("tenant_id", tenantId)`.

What the scanner must do: find the wrapped action, treat only its first parameter as attacker
input, count the wrapper as an auth check, resolve the module-level client through the import,
follow the call into `removeInvoice` with `data.id` tainted, and report the delete.
