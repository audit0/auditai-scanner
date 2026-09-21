import { admin } from "@/lib/supabase/admin";
import { createServerSupabaseClient } from "@/lib/supabase/server";

/**
 * The same route, reading the same table through the same service-role client.
 *
 * The difference is one call: `supabase.auth.getUser()` asks the Auth server whether the token is
 * genuine, so a cookie whose payload was edited to another person's id is rejected before any query
 * runs. `getClaims()`, which verifies the token's signature, would do as well.
 */
export async function GET() {
  const supabase = await createServerSupabaseClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return Response.json({ error: "unauthorized" }, { status: 401 });

  const { data, error } = await admin()
    .from("orders")
    .select("id, item, total_cents")
    .eq("user_id", user.id)
    .order("created_at", { ascending: true });
  if (error) return Response.json({ error: error.message }, { status: 500 });
  return Response.json({ orders: data });
}
