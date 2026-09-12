import { NextResponse } from "next/server";
import { createServerSupabaseClient, createServiceRoleClient } from "@/lib/supabase";

// GET /api/products — the public catalogue. Anyone may read it; audit.config.json says so.
export async function GET() {
  const { data } = await createServiceRoleClient()
    .from("products")
    .select("id, name, price_cents")
    .eq("published", true)
    .order("name");
  return NextResponse.json({ products: data ?? [] });
}

// POST /api/products — adds a product. Only an operator (app_metadata role, set by the service
// role at provisioning time, never by the user) may write to the catalogue.
export async function POST(req: Request) {
  const supabase = await createServerSupabaseClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user || user.app_metadata?.role !== "admin") {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = (await req.json()) as { name?: string; price_cents?: number };
  if (typeof body.name !== "string" || typeof body.price_cents !== "number") {
    return NextResponse.json({ error: "name and price_cents required" }, { status: 400 });
  }
  const { error } = await createServiceRoleClient()
    .from("products")
    .insert({ name: body.name, price_cents: body.price_cents });
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ ok: true }, { status: 201 });
}
