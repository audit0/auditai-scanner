import { cookies } from "next/headers";
import { createRequestClient } from "@/lib/supabase/server";

type Handler<TInput, TResult> = (
  data: TInput,
  user: { id: string; app_metadata: { tenant_id?: string } },
) => Promise<TResult>;

/**
 * next-safe-action / Makerkit-style wrapper: authenticates the caller, then invokes the action
 * with the validated payload and the user. The payload is still attacker-controlled.
 */
export function enhanceAction<TInput, TResult>(handler: Handler<TInput, TResult>) {
  return async (data: TInput): Promise<TResult> => {
    const token = (await cookies()).get("sb-access-token")?.value;
    if (!token) throw new Error("Unauthorized");
    const { data: auth } = await createRequestClient(token).auth.getUser();
    if (!auth.user) throw new Error("Unauthorized");
    return handler(data, auth.user as { id: string; app_metadata: { tenant_id?: string } });
  };
}
