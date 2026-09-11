import { NextResponse } from "next/server";
import { bearerToken, createRequestClient } from "@/lib/supabase";

// GET /api/invoices/:id
// The query runs as the caller (RLS applies) and is explicitly scoped to the caller's tenant.
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const token = bearerToken(req);
  if (!token) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const supabase = createRequestClient(token);
  const { data: userData, error: userError } = await supabase.auth.getUser();
  if (userError || !userData.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { data: profile } = await supabase
    .from("profiles")
    .select("tenant_id")
    .eq("id", userData.user.id)
    .single();
  if (!profile) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const { id } = await params;
  const { data, error } = await supabase
    .from("invoices")
    .select("*")
    .eq("id", id)
    .eq("tenant_id", profile.tenant_id)
    .maybeSingle();

  if (error) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
  if (!data) {
    // Either the invoice does not exist or it belongs to another tenant. Do not distinguish.
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
  return NextResponse.json({ invoice: data });
}
