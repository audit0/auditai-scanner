import { NextResponse } from "next/server";
import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";
import { parseInvoiceSearch } from "@/lib/validate";

// POST /api/invoices — the request body is still validated for shape, but the tenant id used to
// scope the query always comes from the caller's own profile, never from the body.
export async function POST(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json();
  parseInvoiceSearch(body); // validates shape; its tenantId is never trusted for scoping

  const admin = createServiceRoleClient();
  const { data: profile } = await admin
    .from("profiles")
    .select("tenant_id")
    .eq("id", user.id)
    .single();
  if (!profile) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const { data, error } = await admin
    .from("invoices")
    .select("*")
    .eq("tenant_id", profile.tenant_id)
    .order("created_at");

  if (error) return NextResponse.json({ error: "Failed" }, { status: 500 });
  return NextResponse.json({ invoices: data });
}
