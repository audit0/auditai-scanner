# 039-anon-write-policy

`subscribers` is written by a public form, which is a legitimate reason for an insert policy open to
anon: the scanner reports that one as medium and asks you to confirm it is intended. The delete
policy next to it is the defect - `for delete to anon using (true)` lets any visitor empty the
subscriber list through PostgREST without ever touching the application. It can because the list is
also readable with the public key (the admin page reads it with the browser client): a delete through
the Data API always filters on a column, so Postgres applies the SELECT policies too, and a stranger
deletes exactly the rows they can read. Without that read policy the open delete removes nothing
through the API (measured 24 Sept 2026, `docs/realworld/2026-09-24-write-needs-read.md`) and the
scanner reports it as a lead.

The secure twin keeps the public insert and ties the delete to the caller.
