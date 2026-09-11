# Fixture 009: unprotected server action

`deleteInvoice(invoiceId)` is a `"use server"` action bound to a button. Server actions are HTTP endpoints: anyone can POST to them with any argument. This one deletes by id with the service-role client and never checks who is calling. Bob deletes Alice's invoice with one request.

- `vulnerable/`: service-role delete by id, no auth.
- `secure/`: cookie-based user client (RLS applies) plus explicit tenant scope.
