# Fixture 007: admin route without authentication

An "internal" admin endpoint lists every user's email and tenant with the service-role client. It never calls `auth.getUser()` or any auth helper: the URL is the only secret, and URLs are not secrets.

- `vulnerable/`: no authentication at all.
- `secure/`: caller authenticated and role checked via `app_metadata`.
