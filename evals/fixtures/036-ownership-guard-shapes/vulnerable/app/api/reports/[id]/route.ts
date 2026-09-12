import { NextResponse } from "next/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { currentUser } from "@/lib/supabase/server";

// GET /api/reports/[id]?all=1 — reads a report. The owner filter is only added when the caller does
// not ask for `all`, so the caller decides whether ownership is checked.
export async function GET(req: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const admin = createAdminClient();
  let query = admin.from("reports").select("id, title, payload").eq("id", id);
  if (!new URL(req.url).searchParams.get("all")) {
    query = query.eq("owner_id", user.id);
  }
  const { data: report } = await query.maybeSingle();
  if (!report) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json({ report });
}
