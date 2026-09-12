import { createClient } from "@supabase/supabase-js";

/**
 * Service-role client for the public API. An API caller has no Supabase session, so RLS cannot
 * scope anything for it: every query must be scoped by the tenant the key lookup established.
 */
export function createServiceRoleClient() {
  return createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, {
    auth: { persistSession: false },
  });
}
