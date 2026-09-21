import { admin } from "@/lib/supabase/admin";
import { createServerSupabaseClient } from "@/lib/supabase/server";

/**
 * Lists the caller's orders through the service-role client, which is convenient because it needs no
 * policy for this read.
 *
 * That convenience is the hole. The caller is taken from `supabase.auth.getSession()`, which reads
 * the session out of the cookie and does not revalidate it, so `session.user.id` is whatever the
 * browser sent. Row Level Security would have caught an edited token — PostgREST checks the
 * signature — but the service-role client goes around it, so the `eq` below is the only thing
 * between the caller and somebody else's orders.
 */
export async function GET() {
  const supabase = await createServerSupabaseClient();
  const {
    data: { session },
  } = await supabase.auth.getSession();
  if (!session) return Response.json({ error: "unauthorized" }, { status: 401 });

  const { data, error } = await admin()
    .from("orders")
    .select("id, item, total_cents")
    .eq("user_id", session.user.id)
    .order("created_at", { ascending: true });
  if (error) return Response.json({ error: error.message }, { status: 500 });
  return Response.json({ orders: data });
}
