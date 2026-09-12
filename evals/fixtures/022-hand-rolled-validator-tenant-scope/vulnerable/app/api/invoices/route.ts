import { NextResponse } from "next/server";
import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";
import { parseInvoiceSearch } from "@/lib/validate";

// POST /api/invoices — a "search" endpoint: the caller posts filter criteria (tenantId, status)
// instead of query params. The body is validated for shape, but tenantId is still trusted as-is.
export async function POST(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json();
  const query = parseInvoiceSearch(body);

  const admin = createServiceRoleClient();
  const { data, error } = await admin
    .from("invoices")
    .select("*")
    .eq("tenant_id", query.tenantId)
    .order("created_at");

  if (error) return NextResponse.json({ error: "Failed" }, { status: 500 });
  return NextResponse.json({ invoices: data });
}
