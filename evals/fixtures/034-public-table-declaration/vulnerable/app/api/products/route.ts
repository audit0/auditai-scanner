import { NextResponse } from "next/server";
import { createServiceRoleClient } from "@/lib/supabase";

// GET /api/products — the public catalogue. Anyone may read it; audit.config.json says so.
export async function GET() {
  const { data } = await createServiceRoleClient()
    .from("products")
    .select("id, name, price_cents")
    .eq("published", true)
    .order("name");
  return NextResponse.json({ products: data ?? [] });
}

// POST /api/products — adds a product. Nothing checks who is calling: the catalogue being public
// to read does not make it public to write, and the declaration never covers this path.
export async function POST(req: Request) {
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
