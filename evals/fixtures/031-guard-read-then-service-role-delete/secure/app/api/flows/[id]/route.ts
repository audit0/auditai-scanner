import { NextResponse } from "next/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { createServerSupabaseClient } from "@/lib/supabase/server";

/**
 * Ownership guard: reads the flow through the caller's cookie client, so Row Level Security
 * limits the read to the caller's tenant. A flow owned by another tenant comes back as no row,
 * and the route stops with 404 before the privileged delete below runs.
 */
async function requireOwnership(
  flowId: string,
): Promise<{ ok: true } | { ok: false; status: number; error: string }> {
  const supabase = await createServerSupabaseClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return { ok: false, status: 401, error: "Unauthorized" };

  const { data: flow } = await supabase.from("flows").select("id").eq("id", flowId).maybeSingle();
  if (!flow) return { ok: false, status: 404, error: "Not found" };
  return { ok: true };
}

// DELETE /api/flows/[id] — the RLS delete policy refuses everyone, so the route deletes with the
// service role, after the guard above has proved the flow belongs to the caller's tenant.
export async function DELETE(_req: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;

  const guard = await requireOwnership(id);
  if (!guard.ok) return NextResponse.json({ error: guard.error }, { status: guard.status });

  const { error } = await createAdminClient().from("flows").delete().eq("id", id);
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ ok: true });
}
