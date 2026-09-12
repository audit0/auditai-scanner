# Fixture 015: storage download of a user-supplied path via the service role

The Supabase Storage shape of fixture 001. Documents live in a private bucket at
`<user id>/<file name>`, and the storage policies in `supabase/migrations` are correct: a signed-in
user reaches only their own folder. The route handler downloads with the **service-role** client,
which skips storage policies, and takes the object path from the query string.

- `vulnerable/`: `GET /api/documents/download?path=...` authenticates the caller, then
  `supabase.storage.from("documents").download(path)`. Alice downloads Bob's files by passing
  `<bob's id>/report.txt`.
- `secure/`: same service-role client, but the path must start with `${user.id}/` and the rest must
  be a plain file name (no folders, no `..`). Anything else is a 404.
- `supabase/`: shared schema (the two-tenant invoicing base the sandbox seed expects), the private
  `documents` bucket and owner-scoped storage policies.
- `security-test/`: identity matrix. Each user uploads a file into their own folder with their own
  session, then asks the app for their own and the other user's file.

What the scanner must do: recognise `client.storage.from(bucket).download(path)` as a storage access
(not a PostgREST query on a table called "documents"), resolve the client to the service role, mark
the path as request input, and see that the secure path is checked against the session user's id
(`path.startsWith(prefix)` where `prefix = `${user.id}/``).

Status: detected; scan-only. Runtime verification needs `storage-api` in the local Supabase stack,
which the sandbox excludes today.
