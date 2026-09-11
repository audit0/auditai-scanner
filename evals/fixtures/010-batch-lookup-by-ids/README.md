# Fixture 010: batch lookup by ids

A bulk endpoint validates its input carefully (array, 1..100 items) and still leaks: `.in("id", ids)` with the service-role client returns any invoice whose id the caller knows or guesses, across tenants. Input validation is not authorization.

- `vulnerable/`: `.in("id", ids)` only.
- `secure/`: `.in("id", ids).eq("tenant_id", <caller's tenant>)`.
