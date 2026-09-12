# Fixture 032: request rows spread into an insert through `.map()`, against explicit fields

Chat app (the ai-chatbot-supabase shape from the 12 September 2026 real-world run): the client
posts a batch of messages, the route stamps each one with the chat and the caller and inserts the
batch through the service-role client.

- `vulnerable/`: `messages.map((m) => ({ ...m, chat_id: chatId, user_id: user.id }))`. The spread
  keeps every field the caller sent; `chat_id` and `user_id` are then overwritten, but `pinned`,
  `cost_cents` and any other column the caller names go straight into the table.
- `secure/`: `messages.map((m) => ({ chat_id: chatId, user_id: user.id, role: ..., content: ... }))`.
  The rows are built from the caller's values, but every column is named by the server: an
  allow-list, however many rows there are.
- `supabase/`: shared schema and RLS policies (`chats`, `messages`).

What the scanner must do: flag the vulnerable insert with
`supabase.mass-assignment-from-request-body` because the written value is still the caller's whole
object (a spread of each element of the request array), and stay silent on the secure twin, where
`.map()` rebuilds each row from explicit fields. Before this fixture the parser marked any value
derived from the body as "whole input", so the secure shape fired in two independent repositories
(ai-chatbot-supabase, DeskcommCRM) while the actual passthrough (`prisma.user.create({ data: user })`
with the raw body, firestarta) had to stay detected. Whole-input tracking lives in
`packages/parser/src/whole-input.ts`.

Ground truth in `ground-truth.json`, the expected finding in `expected-finding.json`.
