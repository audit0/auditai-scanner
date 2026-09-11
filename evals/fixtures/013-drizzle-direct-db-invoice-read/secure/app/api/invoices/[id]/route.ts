import { and, eq } from "drizzle-orm";
import { NextResponse } from "next/server";
import { invoices, profiles } from "@/db/schema";
import { getUserFromRequest } from "@/lib/auth";
import { db } from "@/lib/db";

// GET /api/invoices/:id — the tenant comes from the caller's profile, never from the request.
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const profile = await db.query.profiles.findFirst({ where: eq(profiles.id, user.id) });
  if (!profile) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const { id } = await params;
  const [invoice] = await db
    .select()
    .from(invoices)
    .where(and(eq(invoices.id, id), eq(invoices.tenantId, profile.tenantId)))
    .limit(1);
  if (!invoice) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json({ invoice });
}
