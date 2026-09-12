# Fixture 036: three ways ownership is established before a service-role query

Project tracker where the API routes authenticate with the cookie client and query through the
service role (RLS bypassed). Each route in the secure twin proves ownership in a different shape
the 13 September 2026 real-world labels found the guard detector missing (16 false positives):

| Route | Secure twin | Vulnerable twin |
|---|---|---|
| `GET /api/projects/[id]/tasks` | reads the **parent** `projects` row with `.eq("owner_id", user.id)` and stops with 404, then reads `tasks` by `project_id` | reads `tasks` by `project_id` straight away |
| `PATCH /api/documents/[id]` | reads the document by id, then **compares in code**: `if (!existing \|\| existing.owner_id !== user.id) return 404` before the update | checks only that the row exists |
| `GET /api/reports/[id]` | builds the query in a variable and adds `.eq("owner_id", user.id)` **conditionally**, unless `app_metadata.role` is `admin` | adds the owner filter unless the caller sends `?all=1` |

What the scanner must do: flag all three vulnerable routes with
`supabase.service-role-object-access-without-tenant-scope` and stay silent on all three secure
routes:

- a guard read of the parent row counts when the guarded query filters by a column that refers to
  the guard's table (a foreign key in the migrations, `tasks.project_id -> projects.id`, or the
  column's name) by the same value, and the guard read is tied to the caller and stops the route;
- an `if` that returns or throws when `row.<owner column> !== <session value>` makes the read its
  own ownership check, and a guard for later queries on that row;
- filters added to a saved query builder belong to the query; one added under an `if` counts only
  when the caller cannot steer the condition (a session value, never a request value).

Ground truth in `ground-truth.json`, the expected finding in `expected-finding.json`.
