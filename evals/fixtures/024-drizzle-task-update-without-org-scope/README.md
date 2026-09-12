# Fixture 024: Drizzle, task status update without org scope

Same shape as 013/014 but a write path instead of a read, and a task-tracker schema instead of
invoices. `lib/db.ts` opens a direct Postgres connection with `drizzle(postgres(DATABASE_URL))`;
nothing goes through PostgREST, so the RLS policy in `drizzle/0000_init.sql` never runs.

- `vulnerable/`: `db.update(tasks).set({ status }).where(eq(tasks.id, id))` after authenticating
  the caller. Any signed-in user can move any org's task to any status.
- `secure/`: the caller's `orgId` comes from `db.query.members.findFirst(...)` by `user.id`, and
  the update adds `and(eq(tasks.id, id), eq(tasks.orgId, member.orgId))`.

What the scanner must do: recognize `db.update(t).set(x).where(...)` as the Drizzle write form,
read `eq(...)`/`and(...)` predicates in the `where` as filters even with a trailing `.returning()`
call, and not flag the membership lookup (identity, not user input). Scan-only fixture.
