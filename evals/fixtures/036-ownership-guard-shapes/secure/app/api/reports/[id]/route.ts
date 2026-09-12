import { NextResponse } from "next/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { currentUser, isAdmin } from "@/lib/supabase/server";

// GET /api/reports/[id] — reads a report. The owner filter is added for everyone but operators,
// and whether the caller is an operator comes from app_metadata, which the caller cannot edit.
export async function GET(_req: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const admin = createAdminClient();
  let query = admin.from("reports").select("id, title, payload").eq("id", id);
  if (!isAdmin(user)) {
    query = query.eq("owner_id", user.id);
  }
  const { data: report } = await query.maybeSingle();
  if (!report) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json({ report });
}
