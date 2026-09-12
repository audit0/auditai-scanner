import { NextResponse } from "next/server";
import { requireApiKey } from "@/lib/api-keys";
import { createServiceRoleClient } from "@/lib/supabase";

// GET /api/v1/me — identity probe of the public API. The key row described is the one the
// credential resolved to; the caller cannot name another.
export async function GET(request: Request) {
  let ctx: Awaited<ReturnType<typeof requireApiKey>>;
  try {
    ctx = await requireApiKey(request);
  } catch {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { data: key } = await createServiceRoleClient()
    .from("api_keys")
    .select("id, tenant_id, name, last_used_at")
    .eq("id", ctx.keyId)
    .maybeSingle();
  if (!key) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json({ tenant: key.tenant_id, key: { id: key.id, name: key.name } });
}
