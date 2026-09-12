import { createClient } from "@supabase/supabase-js";

/**
 * Service-role client kept for admin operations (seeding, background jobs). Not used on the
 * request path for reading a project: the route below reads with the cookie client instead.
 */
export function createAdminClient() {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
    { auth: { persistSession: false } },
  );
}
