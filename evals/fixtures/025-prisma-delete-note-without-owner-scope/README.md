# Fixture 025: Prisma, server action deletes a note without an owner check

The Prisma shape of fixture 009 (unprotected server action), but the action does authenticate
the caller — it just never checks who owns the row. `lib/prisma.ts` holds the usual
`globalThis.prisma ?? new PrismaClient()` singleton; Prisma connects to Postgres directly, so
Supabase RLS never applies and the scanner classifies the client as `direct_db`. Identity comes
from a cookie-based `@supabase/ssr` client (`lib/supabase-server.ts`), which is unrelated to
whether the Prisma query itself is scoped.

- `vulnerable/`: `prisma.note.delete({ where: { id } })` after `getCurrentUser()` succeeds. Any
  signed-in user can delete any other user's note.
- `secure/`: `prisma.note.deleteMany({ where: { id, userId: user.id } })`; a zero-row result is
  reported as not found.

What the scanner must do: follow the server action into `getCurrentUser()` (an identity helper,
not user input) up to `supabase.auth.getUser()`, classify `prisma` as `direct_db` through the
`??` singleton, and read the Prisma `where` object as filters including the plain `id`
shorthand. Scan-only fixture.
