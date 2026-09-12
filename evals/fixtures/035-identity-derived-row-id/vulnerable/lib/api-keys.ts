import { createHash } from "node:crypto";
import { createServiceRoleClient } from "@/lib/supabase";

export interface ApiKeyContext {
  tenantId: string;
  keyId: string;
}

export function hashApiKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

function extractKey(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (!header) return null;
  const value = header.startsWith("Bearer ") ? header.slice("Bearer ".length).trim() : header.trim();
  return value.length > 0 ? value : null;
}

/** The api_keys row behind a presented key. The lookup by hash is the authentication itself. */
export async function findActiveKeyByHash(hash: string) {
  const { data, error } = await createServiceRoleClient()
    .from("api_keys")
    .select("id, tenant_id, revoked_at")
    .eq("key_hash", hash)
    .maybeSingle();
  if (error || !data) return null;
  if (data.revoked_at) return null;
  return data;
}

/** Fire-and-forget: remember when a key was last used. */
export function touchLastUsed(id: string): void {
  void createServiceRoleClient()
    .from("api_keys")
    .update({ last_used_at: new Date().toISOString() })
    .eq("id", id)
    .then(() => undefined);
}

/** Authenticates a public-API request; throws when the key is missing, unknown or revoked. */
export async function requireApiKey(request: Request): Promise<ApiKeyContext> {
  const presented = extractKey(request);
  if (!presented) throw new Error("unauthorized");
  const row = await findActiveKeyByHash(hashApiKey(presented));
  if (!row) throw new Error("unauthorized");
  return { tenantId: row.tenant_id, keyId: row.id };
}
