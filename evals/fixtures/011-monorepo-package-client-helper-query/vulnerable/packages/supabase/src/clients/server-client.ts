import { createClient } from "@supabase/supabase-js";

/** Per-request client carrying the caller's JWT: queries run under RLS as that user. */
export function getSupabaseServerClient(token: string) {
  return createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { headers: { Authorization: `Bearer ${token}` } },
  });
}
