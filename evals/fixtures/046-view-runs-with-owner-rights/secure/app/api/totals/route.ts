import { NextResponse } from "next/server";
import { createUserClient } from "@/lib/supabase";

// GET /api/totals - a signed-in user's invoice totals. The route reads the view and trusts the
// policies on invoices to keep tenants apart, which a view running with its owner's rights ignores.
export async function GET() {
  const supabase = await createUserClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { data } = await supabase.from("invoice_totals").select("tenant_id, total");
  return NextResponse.json({ totals: data ?? [] });
}
