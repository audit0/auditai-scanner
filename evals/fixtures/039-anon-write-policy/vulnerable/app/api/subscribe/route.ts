import { NextResponse } from "next/server";
import { createAnonClient } from "@/lib/supabase";

// POST /api/subscribe - the public form. The row is written with the anon key, so the policies on
// `subscribers` are the only thing standing between a visitor and the table.
export async function POST(req: Request) {
  const body = (await req.json()) as { email?: string };
  if (typeof body.email !== "string" || !body.email.includes("@")) {
    return NextResponse.json({ error: "email required" }, { status: 400 });
  }
  const { error } = await createAnonClient().from("subscribers").insert({ email: body.email });
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ ok: true }, { status: 201 });
}
