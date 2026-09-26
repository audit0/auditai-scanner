import { NextResponse } from "next/server";
import { bearerToken, createRequestClient } from "@/lib/supabase";

// GET /api/invoices/search?q=acme
// Invoice search for the tenant dashboard, answered by public.search_invoices().
export async function GET(req: Request) {
  const token = bearerToken(req);
  if (!token) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const supabase = createRequestClient(token);
  const { data: userData, error: userError } = await supabase.auth.getUser();
  if (userError || !userData.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const q = new URL(req.url).searchParams.get("q") ?? "";
  const { data, error } = await supabase.rpc("search_invoices", { p_customer: q });
  if (error) {
    return NextResponse.json({ error: "Search failed" }, { status: 400 });
  }
  return NextResponse.json({ invoices: data ?? [] });
}
