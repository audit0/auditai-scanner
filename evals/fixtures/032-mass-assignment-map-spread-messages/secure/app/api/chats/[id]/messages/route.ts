import { NextResponse } from "next/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { createServerSupabaseClient } from "@/lib/supabase/server";

type IncomingMessage = { role?: unknown; content?: unknown };

// POST /api/chats/[id]/messages — append a batch of messages to the caller's chat.
// Every column is named by the server; the caller only supplies role and content.
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
  const rows = messages.map((m) => ({
    chat_id: chatId,
    user_id: user.id,
    role: m.role === "assistant" ? "assistant" : "user",
    content: typeof m.content === "string" ? m.content.slice(0, 4000) : "",
  }));

  const { error } = await createAdminClient().from("messages").insert(rows);
  if (error) return NextResponse.json({ error: "Failed" }, { status: 400 });
  return NextResponse.json({ saved: rows.length });
}
