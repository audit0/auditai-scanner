import { NextResponse } from "next/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { currentUser } from "@/lib/supabase/server";

// GET /api/projects/[id]/tasks — lists the tasks of a project. Signed in, but the project is never
// checked to be the caller's: any user lists any project's tasks.
export async function GET(_req: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const admin = createAdminClient();
  const { data: tasks } = await admin.from("tasks").select("*").eq("project_id", id);
  return NextResponse.json({ tasks: tasks ?? [] });
}
