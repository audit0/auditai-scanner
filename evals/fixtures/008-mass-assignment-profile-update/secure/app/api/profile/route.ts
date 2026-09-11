import { NextResponse } from "next/server";
import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";

// PATCH /api/profile — only the fields a user may change are copied from the body.
export async function PATCH(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = (await req.json()) as { display_name?: unknown };
  const displayName = typeof body.display_name === "string" ? body.display_name.slice(0, 80) : null;
  if (displayName === null) return NextResponse.json({ error: "display_name is required" }, { status: 400 });

  const admin = createServiceRoleClient();
  const { data, error } = await admin
    .from("profiles")
    .update({ display_name: displayName })
    .eq("id", user.id)
    .select("id, email, display_name")
    .single();
  if (error) return NextResponse.json({ error: "Failed" }, { status: 400 });
  return NextResponse.json({ profile: data });
}
