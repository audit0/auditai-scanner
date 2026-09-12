# Fixture 021: dynamic page renders a row read through a service-role admin client

`app/projects/[id]/page.tsx` is a server component, not a route handler or a server action — it is
still an HTTP entry point (a GET that renders on the server), and AI tools reach for the same
"admin client" habit inside pages as they do inside route handlers.

- `vulnerable/`: the page checks who is signed in with the cookie client's `auth.getUser()` (redirects
  to `/login` otherwise), then fetches the project to render with the **admin** client filtered by
  `id` only. Any signed-in user who knows or guesses a project id can view another tenant's project.
- `secure/`: the page renders with the cookie client itself, so the `projects: tenant members read`
  RLS policy scopes the row to the caller's tenant automatically.
- `supabase/`: shared schema and RLS policies (same as fixture 019: `tenants`, `profiles`, `projects`).

What the scanner must do: treat `app/projects/[id]/page.tsx`'s default export as an entry point
(`PAGE /projects/[id]`) with `params.id` as user-controlled input, and follow the query into the
admin client the same way it does for a route handler.

Ground truth in `ground-truth.json`, the expected finding in `expected-finding.json`.
