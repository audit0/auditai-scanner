import { createClient } from "@supabase/supabase-js";
import { getServiceRoleKey } from "../get-service-role-key";

/** Admin client: service role, bypasses Row Level Security. */
export function getSupabaseServerAdminClient() {
  return createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, getServiceRoleKey(), {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}
