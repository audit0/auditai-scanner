import { NextResponse } from "next/server";
import { createServerSupabaseClient } from "@/lib/supabase/server";

// PATCH /api/profile — only the fields a user may change are copied from the body. RLS still
// scopes the row to the caller; the allow-list additionally stops column-level over-posting.
export async function PATCH(req: Request) {
  const supabase = await createServerSupabaseClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = (await req.json()) as { display_name?: unknown };
  const displayName = typeof body.display_name === "string" ? body.display_name.slice(0, 80) : null;
  if (displayName === null) {
    return NextResponse.json({ error: "display_name is required" }, { status: 400 });
  }

  const { data, error } = await supabase
    .from("profiles")
    .update({ display_name: displayName })
    .eq("id", user.id)
    .select("id, email, display_name, role")
    .single();
  if (error) return NextResponse.json({ error: "Failed" }, { status: 400 });
  return NextResponse.json({ profile: data });
}
