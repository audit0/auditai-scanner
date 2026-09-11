import { supabaseAdmin } from "@/lib/supabase/admin";

/** Deletes an invoice by id, but only inside the caller's tenant. */
export async function removeInvoice(invoiceId: string, tenantId: string) {
  const { error } = await supabaseAdmin
    .from("invoices")
    .delete()
    .eq("id", invoiceId)
    .eq("tenant_id", tenantId);
  if (error) throw new Error("Failed to delete invoice");
}
