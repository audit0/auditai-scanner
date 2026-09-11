import { loadInvoice } from "@kit/invoices/server";
import { requireUser } from "@kit/supabase/require-user";
import { getSupabaseServerAdminClient } from "@kit/supabase/server-admin-client";
import { getSupabaseServerClient } from "@kit/supabase/server-client";
import { NextResponse } from "next/server";
import { bearerToken } from "~/lib/http";

// GET /api/invoices/:id — authenticates the caller, then loads the invoice with the ADMIN client.
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const token = bearerToken(req);
  if (!token) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const user = await requireUser(getSupabaseServerClient(token));
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id } = await params;
  const invoice = await loadInvoice(getSupabaseServerAdminClient(), id);
  if (!invoice) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json({ invoice });
}
