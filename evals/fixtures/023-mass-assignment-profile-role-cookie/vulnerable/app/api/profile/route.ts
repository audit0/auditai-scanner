import { NextResponse } from "next/server";
import { createServerSupabaseClient } from "@/lib/supabase/server";

// PATCH /api/profile — "update my profile". Row Level Security correctly scopes the row to the
// caller (the update policy checks id = auth.uid()), but every column in the JSON body is still
// written as-is: RLS restricts rows, not columns.
export async function PATCH(req: Request) {
  const supabase = await createServerSupabaseClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json();
  const { data, error } = await supabase
    .from("profiles")
    .update(body)
    .eq("id", user.id)
    .select()
    .single();
  if (error) return NextResponse.json({ error: "Failed" }, { status: 400 });
  return NextResponse.json({ profile: data });
}
