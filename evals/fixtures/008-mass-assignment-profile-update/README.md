# Fixture 008: mass assignment from the request body

The profile update writes `req.json()` straight into `profiles.update(...)`. The row is correctly scoped to the caller, but the payload is not: `{ "display_name": "x", "role": "admin", "tenant_id": "<tenant B>" }` promotes the user and moves them into another tenant.

- `vulnerable/`: `update(body)`.
- `secure/`: explicit allow-list `{ display_name }` with validation.
