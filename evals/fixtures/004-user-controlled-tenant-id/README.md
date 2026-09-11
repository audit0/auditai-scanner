# Fixture 004: tenant id taken from the request

The list endpoint is "scoped by tenant", which is why it passes a casual review. But the tenant id is a query-string parameter chosen by the caller, and the query runs with the service-role client. Alice passes Bob's tenant id and gets Tenant B's invoices.

- `vulnerable/`: `?tenant=` from the URL drives `.eq("tenant_id", ...)`.
- `secure/`: tenant id is looked up from the caller's profile by `auth.uid()`.
