import { createClient } from "@supabase/supabase-js";

/**
 * Service-role client. It bypasses Row Level Security, so every query made with it is scoped by the
 * application and by nothing else.
 */
export function admin() {
  return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, {
    auth: { persistSession: false },
  });
}
