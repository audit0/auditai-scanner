import { NextResponse } from "next/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { createServerSupabaseClient } from "@/lib/supabase/server";

type IncomingMessage = { role: "user" | "assistant"; content: string };

// POST /api/chats/[id]/messages — append a batch of messages to the caller's chat.
// Each posted object is spread into the row, so any column the caller names is written too.
export async function POST(req: Request, context: { params: Promise<{ id: string }> }) {
  const { id: chatId } = await context.params;

  const supabase = await createServerSupabaseClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { data: chat } = await supabase.from("chats").select("id").eq("id", chatId).maybeSingle();
  if (!chat) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const { messages } = (await req.json()) as { messages: IncomingMessage[] };
  const rows = messages.map((m) => ({ ...m, chat_id: chatId, user_id: user.id }));

  const { error } = await createAdminClient().from("messages").insert(rows);
  if (error) return NextResponse.json({ error: "Failed" }, { status: 400 });
  return NextResponse.json({ saved: rows.length });
}
