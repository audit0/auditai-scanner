import { eq } from "drizzle-orm";
import { NextResponse } from "next/server";
import { invoices } from "@/db/schema";
import { getUserFromRequest } from "@/lib/auth";
import { db } from "@/lib/db";

// GET /api/invoices/:id — Drizzle talks to Postgres directly; the RLS policy on invoices never runs.
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id } = await params;
  const [invoice] = await db.select().from(invoices).where(eq(invoices.id, id)).limit(1);
  if (!invoice) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json({ invoice });
}
