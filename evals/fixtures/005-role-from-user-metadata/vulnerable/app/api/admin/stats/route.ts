import { NextResponse } from "next/server";
import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";

// GET /api/admin/stats — admin-only revenue across all tenants.
export async function GET(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  // user_metadata is set from the signup form... and can be changed by the user at any time.
  if (user.user_metadata?.role !== "admin") return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const admin = createServiceRoleClient();
  const { data, error } = await admin.from("invoices").select("amount_cents");
  if (error) return NextResponse.json({ error: "Failed" }, { status: 500 });
  const total = (data ?? []).reduce((sum, row) => sum + row.amount_cents, 0);
  return NextResponse.json({ invoices: data?.length ?? 0, total_cents: total });
}
