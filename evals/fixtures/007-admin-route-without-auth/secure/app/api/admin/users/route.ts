import { NextResponse } from "next/server";
import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";

// GET /api/admin/users — authenticated and restricted to admins (role lives in app_metadata).
export async function GET(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (user.app_metadata?.role !== "admin") return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const admin = createServiceRoleClient();
  const { data, error } = await admin.from("profiles").select("id, email, tenant_id").order("email");
  if (error) return NextResponse.json({ error: "Failed" }, { status: 500 });
  return NextResponse.json({ users: data });
}
