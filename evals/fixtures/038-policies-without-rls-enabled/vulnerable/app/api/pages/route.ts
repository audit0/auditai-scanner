import { NextResponse } from "next/server";
import { createUserClient } from "@/lib/supabase";

// GET /api/pages - every page the caller's workspaces contain. The route relies entirely on the
// policies, which is exactly why a table whose RLS was never enabled is a hole.
export async function GET() {
  const supabase = await createUserClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { data } = await supabase.from("pages").select("id, title, body");
  return NextResponse.json({ pages: data ?? [] });
}
