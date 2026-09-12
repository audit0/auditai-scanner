import { NextResponse } from "next/server";
import { createUserClient } from "@/lib/supabase-server";

// GET /api/projects/:id — relies entirely on RLS to keep owners apart.
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const supabase = await createUserClient();
  const { data: auth } = await supabase.auth.getUser();
  if (!auth.user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id } = await params;
  const { data } = await supabase.from("projects").select("*").eq("id", id).maybeSingle();
  if (!data) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json({ project: data });
}
