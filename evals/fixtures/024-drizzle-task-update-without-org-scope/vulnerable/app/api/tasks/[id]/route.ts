import { eq } from "drizzle-orm";
import { NextResponse } from "next/server";
import { tasks } from "@/db/schema";
import { getUserFromRequest } from "@/lib/auth";
import { db } from "@/lib/db";

// PATCH /api/tasks/:id — updates a task's status. Drizzle talks to Postgres directly, so the RLS
// policy on tasks never runs for this query.
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id } = await params;
  const body = (await req.json()) as { status?: string };
  const status = body.status;
  if (!status) return NextResponse.json({ error: "status is required" }, { status: 400 });

  const [task] = await db.update(tasks).set({ status }).where(eq(tasks.id, id)).returning();
  if (!task) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json({ task });
}
