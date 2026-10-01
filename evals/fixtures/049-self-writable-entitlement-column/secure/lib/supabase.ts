import { createClient } from "@supabase/supabase-js";

/**
 * Per-request client that carries the caller's JWT. Every query runs under RLS as that user.
 * The service-role key is not used on any request path.
 */
export function createRequestClient(token: string) {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      auth: { persistSession: false, autoRefreshToken: false },
      global: { headers: { Authorization: `Bearer ${token}` } },
    },
  );
}

export function bearerToken(req: Request): string | null {
  const auth = req.headers.get("authorization") ?? "";
  return auth.startsWith("Bearer ") ? auth.slice(7) : null;
}
