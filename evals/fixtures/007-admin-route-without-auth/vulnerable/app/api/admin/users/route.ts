import { NextResponse } from "next/server";
import { createServiceRoleClient } from "@/lib/supabase";

// GET /api/admin/users — "internal" endpoint used by the admin dashboard. Nothing checks who is calling.
export async function GET() {
  const admin = createServiceRoleClient();
  const { data, error } = await admin.from("profiles").select("id, email, tenant_id").order("email");
  if (error) return NextResponse.json({ error: "Failed" }, { status: 500 });
  return NextResponse.json({ users: data });
}
