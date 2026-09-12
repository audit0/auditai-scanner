import { createClient } from "@supabase/supabase-js";

/** Service-role client: the catalogue is served from the server, RLS bypassed. */
export function createServiceRoleClient() {
  return createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, {
    auth: { persistSession: false },
  });
}
