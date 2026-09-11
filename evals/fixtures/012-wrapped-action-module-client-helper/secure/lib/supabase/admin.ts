import { createClient } from "@supabase/supabase-js";

/** One module-level admin client reused by every helper. Service role: RLS does not apply. */
export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
  { auth: { persistSession: false } },
);
