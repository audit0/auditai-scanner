import { createClient } from "@supabase/supabase-js";
import { NextResponse } from "next/server";
import { bearerToken, createRequestClient } from "@/lib/supabase";

// GET /api/admin/users
// Every user of every tenant, for the operator console. Only user_roles.role = 'admin' may call it.
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
    .from("user_roles")
    .select("role")
    .eq("user_id", user.id)
    .single();
  if (profile?.role !== "admin") {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const admin = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
    { auth: { persistSession: false } },
  );
  const { data } = await admin.from("profiles").select("id, email, tenant_id");
  return NextResponse.json({ users: data ?? [] });
}
