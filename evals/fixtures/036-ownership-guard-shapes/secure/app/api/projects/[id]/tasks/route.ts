import { NextResponse } from "next/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { currentUser } from "@/lib/supabase/server";

// GET /api/projects/[id]/tasks — lists the tasks of a project. Ownership is established on the
// parent row: the project is read with the caller as owner and the route stops when it is missing;
// the tasks are then read by project_id through the service role.
export async function GET(_req: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const admin = createAdminClient();
  const { data: project } = await admin
    .from("projects")
    .select("id")
    .eq("id", id)
    .eq("owner_id", user.id)
    .maybeSingle();
  if (!project) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const { data: tasks } = await admin.from("tasks").select("*").eq("project_id", id);
  return NextResponse.json({ tasks: tasks ?? [] });
}
