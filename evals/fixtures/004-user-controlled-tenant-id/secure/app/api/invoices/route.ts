import { NextResponse } from "next/server";
import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";

// GET /api/invoices — the tenant comes from the caller's profile, never from the request.
export async function GET(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const admin = createServiceRoleClient();
  const { data: profile } = await admin.from("profiles").select("tenant_id").eq("id", user.id).single();
  if (!profile) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const { data, error } = await admin.from("invoices").select("*").eq("tenant_id", profile.tenant_id).order("created_at");
  if (error) return NextResponse.json({ error: "Failed" }, { status: 500 });
  return NextResponse.json({ invoices: data });
}
