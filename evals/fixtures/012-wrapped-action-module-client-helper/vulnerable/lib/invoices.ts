import { supabaseAdmin } from "@/lib/supabase/admin";

/** Deletes an invoice by id. Nothing here knows which tenant is calling. */
export async function removeInvoice(invoiceId: string) {
  const { error } = await supabaseAdmin.from("invoices").delete().eq("id", invoiceId);
  if (error) throw new Error("Failed to delete invoice");
}
