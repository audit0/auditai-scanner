import { createClient } from "@supabase/supabase-js";

/**
 * Service-role client for the few writes RLS refuses to the signed-in user (deleting a flow).
 * It bypasses Row Level Security entirely, so every caller must check ownership itself.
 */
export function createAdminClient() {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
    { auth: { persistSession: false } },
  );
}
