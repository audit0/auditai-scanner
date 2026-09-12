import { NextResponse } from "next/server";
import { requireApiKey, touchLastUsed } from "@/lib/api-keys";
import { createServiceRoleClient } from "@/lib/supabase";

// GET /api/v1/me?key=<id> — identity probe of the public API. The key row to describe (and to stamp
// as used) is taken from the query string, so a caller with any valid key reads and touches any
// other tenant's key row.
export async function GET(request: Request) {
  let ctx: Awaited<ReturnType<typeof requireApiKey>>;
  try {
    ctx = await requireApiKey(request);
  } catch {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const keyId = new URL(request.url).searchParams.get("key") ?? ctx.keyId;
  touchLastUsed(keyId);
  const { data: key } = await createServiceRoleClient()
    .from("api_keys")
    .select("id, tenant_id, name, last_used_at")
    .eq("id", keyId)
    .maybeSingle();
  if (!key) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json({ tenant: key.tenant_id, key: { id: key.id, name: key.name } });
}
