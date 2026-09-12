import { NextResponse } from "next/server";
import { createUserClient } from "@/lib/supabase";

// GET /api/notes - the caller's notes. RLS decides which rows come back, which is why the policy
// behind it has to be right.
export async function GET() {
  const supabase = await createUserClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { data } = await supabase.from("notes").select("id, body, created_at").order("created_at");
  return NextResponse.json({ notes: data ?? [] });
}
