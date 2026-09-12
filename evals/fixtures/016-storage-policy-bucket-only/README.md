# Fixture 016: storage policy that only checks the bucket

The app does the right thing: `GET /api/documents/download?path=...` downloads with a per-request
client carrying the caller's JWT, so the storage policies on `storage.objects` decide what the caller
may read. The read policy is the one AI tools generate for "allow authenticated users to read
documents": `using (bucket_id = 'documents')`. It checks the bucket only, so every signed-in user
reads every user's files, through this route or straight through the Storage API.

- `vulnerable/supabase/migrations`: `for select to authenticated using (bucket_id = 'documents')`.
- `secure/supabase/migrations`: `using (bucket_id = 'documents' and (storage.foldername(name))[1] = (select auth.uid())::text)`.
- The route handler and `lib/` are identical in both variants; the upload policy is owner-scoped in both.
- `security-test/`: identity matrix. Each user uploads a file into their own folder with their own
  session, then asks the app for their own and the other user's file.

What the scanner must do: find the policy on `storage.objects` in the migrations, see that its USING
clause constrains nothing but `bucket_id` on a bucket declared private, report it once with the
policy location, and name the route that relies on it. The owner-scoped upload policy and the secure
read policy must stay silent.

Status: detected; scan-only. Runtime verification needs `storage-api` in the local Supabase stack,
which the sandbox excludes today.
