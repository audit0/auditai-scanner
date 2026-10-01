import { NextResponse } from "next/server";
import { bearerToken, createRequestClient } from "@/lib/supabase";

// POST /api/invoices/export
// A paid export of the caller's tenant invoices. Each export costs one credit; the plan the tenant
// bought tops profiles.credits up, and the route refuses with 402 when none are left.
export async function POST(req: Request) {
  const token = bearerToken(req);
  if (!token) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const supabase = createRequestClient(token);
  const { data: userData, error: userError } = await supabase.auth.getUser();
  const user = userData.user;
  if (userError || !user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { data: profile } = await supabase
    .from("profiles")
    .select("credits")
    .eq("id", user.id)
    .single();
  if (!profile || profile.credits <= 0) {
    return NextResponse.json({ error: "No export credits left" }, { status: 402 });
  }

  const { error: spendError } = await supabase.rpc("spend_export_credit");
  if (spendError) {
    return NextResponse.json({ error: "No export credits left" }, { status: 402 });
  }
  const { data } = await supabase
    .from("invoices")
    .select("id, customer_name, amount_cents, created_at");
  return NextResponse.json({ invoices: data ?? [] });
}
