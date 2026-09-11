import { NextResponse } from "next/server";
import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";

// POST /api/invoices/batch { ids: string[] } — bulk fetch for the dashboard table.
export async function POST(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { ids } = (await req.json()) as { ids?: string[] };
  if (!Array.isArray(ids) || ids.length === 0 || ids.length > 100) {
    return NextResponse.json({ error: "ids must be 1..100 items" }, { status: 400 });
  }

  const admin = createServiceRoleClient();
  const { data, error } = await admin.from("invoices").select("*").in("id", ids);
  if (error) return NextResponse.json({ error: "Failed" }, { status: 500 });
  return NextResponse.json({ invoices: data });
}
