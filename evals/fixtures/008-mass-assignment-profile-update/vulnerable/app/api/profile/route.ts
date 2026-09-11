import { NextResponse } from "next/server";
import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";

// PATCH /api/profile — "update my profile". The whole JSON body is written to the row.
export async function PATCH(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json();
  const admin = createServiceRoleClient();
  const { data, error } = await admin.from("profiles").update(body).eq("id", user.id).select().single();
  if (error) return NextResponse.json({ error: "Failed" }, { status: 400 });
  return NextResponse.json({ profile: data });
}
