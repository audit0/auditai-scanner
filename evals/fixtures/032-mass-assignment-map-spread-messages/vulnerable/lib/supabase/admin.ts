import { createClient } from "@supabase/supabase-js";

/**
 * Service-role client for writes the app performs on the user's behalf (assistant replies are
 * inserted alongside the user's messages). It bypasses Row Level Security entirely.
 */
export function createAdminClient() {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
    { auth: { persistSession: false } },
  );
}
