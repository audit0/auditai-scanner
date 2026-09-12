import { and, eq } from "drizzle-orm";
import { NextResponse } from "next/server";
import { members, tasks } from "@/db/schema";
import { getUserFromRequest } from "@/lib/auth";
import { db } from "@/lib/db";

// PATCH /api/tasks/:id — the org comes from the caller's membership row, never from the request.
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const member = await db.query.members.findFirst({ where: eq(members.userId, user.id) });
  if (!member) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const { id } = await params;
  const body = (await req.json()) as { status?: string };
  const status = body.status;
  if (!status) return NextResponse.json({ error: "status is required" }, { status: 400 });

  const [task] = await db
    .update(tasks)
    .set({ status })
    .where(and(eq(tasks.id, id), eq(tasks.orgId, member.orgId)))
    .returning();
  if (!task) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json({ task });
}
