import { createClient } from "@supabase/supabase-js";

/** Resolves the caller from the bearer token through Supabase Auth. Identity only; authorization happens in the query. */
export async function getUserFromRequest(req: Request) {
  const auth = req.headers.get("authorization") ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return null;
  const sb = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    auth: { persistSession: false },
  });
  const { data, error } = await sb.auth.getUser(token);
  if (error || !data.user) return null;
  return data.user;
}
