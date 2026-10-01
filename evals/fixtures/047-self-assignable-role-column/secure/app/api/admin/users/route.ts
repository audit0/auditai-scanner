import { createClient } from "@supabase/supabase-js";
import { NextResponse } from "next/server";
import { bearerToken, createRequestClient } from "@/lib/supabase";

// GET /api/admin/users
// Every user of every tenant, for the operator console. Only profiles.role = 'admin' may call it.
export async function GET(req: Request) {
  const token = bearerToken(req);
  if (!token) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const supabase = createRequestClient(token);
  const { data: userData, error: userError } = await supabase.auth.getUser();
  const user = userData.user;
  if (userError || !user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { data: profile } = await supabase
    .from("profiles")
    .select("role")
    .eq("id", user.id)
    .single();
  if (profile?.role !== "admin") {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const admin = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
    { auth: { persistSession: false } },
  );
  const { data } = await admin.from("profiles").select("id, email, full_name, role, tenant_id");
  return NextResponse.json({ users: data ?? [] });
}

// POST /api/admin/users
// An admin adds a member to their own tenant: the profile row every user has, created with the
// service role after the same admin check. Its role is always 'member'.
export async function POST(req: Request) {
  const token = bearerToken(req);
  if (!token) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const supabase = createRequestClient(token);
  const { data: userData, error: userError } = await supabase.auth.getUser();
  const user = userData.user;
  if (userError || !user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { data: profile } = await supabase
    .from("profiles")
    .select("role, tenant_id")
    .eq("id", user.id)
    .single();
  if (profile?.role !== "admin") {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const body = (await req.json()) as { userId?: unknown; email?: unknown };
  if (typeof body.userId !== "string" || typeof body.email !== "string") {
    return NextResponse.json({ error: "userId and email are required" }, { status: 400 });
  }
  const admin = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
    { auth: { persistSession: false } },
  );
  const { error } = await admin.from("profiles").insert({
    id: body.userId,
    tenant_id: profile.tenant_id,
    email: body.email,
    role: "member",
  });
  if (error) {
    return NextResponse.json({ error: "Could not add the member" }, { status: 400 });
  }
  return NextResponse.json({ ok: true }, { status: 201 });
}
