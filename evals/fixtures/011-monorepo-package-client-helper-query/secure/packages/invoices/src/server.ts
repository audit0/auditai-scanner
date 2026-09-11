import type { SupabaseClient } from "@supabase/supabase-js";

/** Loads one invoice by id for the caller's tenant. Runs under RLS with the caller's client. */
export async function loadInvoice(client: SupabaseClient, invoiceId: string, tenantId: string) {
  const { data } = await client
    .from("invoices")
    .select("*")
    .eq("id", invoiceId)
    .eq("tenant_id", tenantId)
    .maybeSingle();
  return data;
}
