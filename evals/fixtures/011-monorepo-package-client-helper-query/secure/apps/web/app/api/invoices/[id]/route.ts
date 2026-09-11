import { loadInvoice } from "@kit/invoices/server";
import { requireUser } from "@kit/supabase/require-user";
import { getSupabaseServerClient } from "@kit/supabase/server-client";
import { NextResponse } from "next/server";
import { bearerToken } from "~/lib/http";

// GET /api/invoices/:id — the caller's own client (RLS applies) plus an explicit tenant scope.
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const token = bearerToken(req);
  if (!token) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const client = getSupabaseServerClient(token);
  const user = await requireUser(client);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { data: profile } = await client.from("profiles").select("tenant_id").eq("id", user.id).single();
  if (!profile) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const { id } = await params;
  const invoice = await loadInvoice(client, id, profile.tenant_id);
  if (!invoice) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json({ invoice });
}
