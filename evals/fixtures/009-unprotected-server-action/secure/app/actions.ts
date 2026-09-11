"use server";

import { revalidatePath } from "next/cache";
import { createUserClient } from "@/lib/supabase-server";

// Runs as the caller: RLS limits the delete to their tenant, and the tenant is checked explicitly too.
export async function deleteInvoice(invoiceId: string) {
  const supabase = await createUserClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) throw new Error("Unauthorized");

  const { data: profile } = await supabase.from("profiles").select("tenant_id").eq("id", user.id).single();
  if (!profile) throw new Error("Forbidden");

  const { error } = await supabase.from("invoices").delete().eq("id", invoiceId).eq("tenant_id", profile.tenant_id);
  if (error) throw new Error("Failed to delete invoice");
  revalidatePath("/invoices");
}
