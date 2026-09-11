import type { SupabaseClient } from "@supabase/supabase-js";

/** Resolves the caller from the client's JWT, or null. */
export async function requireUser(client: SupabaseClient) {
  const { data, error } = await client.auth.getUser();
  if (error || !data.user) return null;
  return data.user;
}
