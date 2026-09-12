# Fixture 020: server action reads its id from `FormData.get()` into a local `const`

Minimal multi-tenant documents app with the most common shape AI tools write for a form-bound server
action: `<form action={deleteDocument}>`, and the action reads the id out of `FormData` into a named
`const` before using it (for readability, and because the value usually needs a cast).

- `vulnerable/`: `deleteDocument(formData)` authenticates the caller, then deletes through a
  **service-role** client filtered by `id` only. RLS on `documents` is correct, but the service role
  bypasses it, so any signed-in user can delete any tenant's document by posting its id.
  The listing page `PAGE /documents` also reads through the admin client with no auth check at all:
  a real, separate, correctly-detected bug (`supabase.service-role-query-without-authentication`),
  deliberately left in to keep the fixture realistic, same as the listing page in fixture 009.
- `secure/`: the action deletes through the user-scoped client (RLS applies) and additionally scopes
  the delete by the caller's `tenant_id` from `profiles`; the page reads through the user-scoped client.
- `supabase/`: shared schema and RLS policies (`tenants`, `profiles`, `documents`).

```ts
export async function deleteDocument(formData: FormData) {
  const supabase = await createUserClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) throw new Error("Unauthorized");

  const id = formData.get("id") as string;
  const admin = createServiceRoleClient();
  const { error } = await admin.from("documents").delete().eq("id", id);
  ...
}
```

## What the scanner must do

Follow taint from a tainted method-call **receiver** into the call's result: `formData` is an
attacker-controlled action argument, so `formData.get("id")` is attacker-controlled too, and so is
the `const id` it initializes. The same rule covers `(await req.formData()).get(...)`,
`URLSearchParams.get`, `Map.get` on a tainted map, and anything read off the incoming request
(`req.headers.get(...)`) inside a helper.

History: this pair sat in `evals/pending/` until 12 September 2026 because the parser tainted a call
result only from tainted arguments, never from a tainted receiver (the inline form
`.eq("id", formData.get("id") as string)` was already detected, the two-step form was not). Fixed in
`analyzeFrame` (`receiverTainted` in `packages/parser/src/parse-project.ts`). A value derived through a
receiver is tainted but is not a whole request object (see `packages/parser/src/whole-input.ts`), so
`formData.get("id")` never counts as mass assignment.

Ground truth in `ground-truth.json`, the expected finding in `expected-finding.json`.
