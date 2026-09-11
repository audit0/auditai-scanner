import { NextResponse } from "next/server";
import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";

// GET /api/invoices?tenant=<uuid> — the client tells the server which tenant to list.
export async function GET(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const tenantId = new URL(req.url).searchParams.get("tenant");
  if (!tenantId) return NextResponse.json({ error: "tenant is required" }, { status: 400 });

  const admin = createServiceRoleClient();
  const { data, error } = await admin.from("invoices").select("*").eq("tenant_id", tenantId).order("created_at");
  if (error) return NextResponse.json({ error: "Failed" }, { status: 500 });
  return NextResponse.json({ invoices: data });
}
