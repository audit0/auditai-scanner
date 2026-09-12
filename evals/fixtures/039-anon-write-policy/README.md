# 039-anon-write-policy

`subscribers` is written by a public form, which is a legitimate reason for an insert policy open to
anon: the scanner reports that one as medium and asks you to confirm it is intended. The delete
policy next to it is the defect - `for delete to anon using (true)` lets any visitor empty the
subscriber list through PostgREST without ever touching the application.

The secure twin keeps the public insert and ties the delete to the caller.
