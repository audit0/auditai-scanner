import { NextResponse } from "next/server";
import { getUserFromRequest } from "@/lib/auth";
import { prisma } from "@/lib/prisma";

// GET /api/invoices/:id — scoped by the caller's tenant, which comes from their profile row.
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const profile = await prisma.profile.findUnique({ where: { id: user.id } });
  if (!profile) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const { id } = await params;
  const invoice = await prisma.invoice.findFirst({ where: { id, tenantId: profile.tenantId } });
  if (!invoice) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json({ invoice });
}
