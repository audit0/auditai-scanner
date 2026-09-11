import type { SupabaseClient } from "@supabase/supabase-js";

/** Loads one invoice by id. The caller decides which client this runs with. */
export async function loadInvoice(client: SupabaseClient, invoiceId: string) {
  const { data } = await client.from("invoices").select("*").eq("id", invoiceId).maybeSingle();
  return data;
}
