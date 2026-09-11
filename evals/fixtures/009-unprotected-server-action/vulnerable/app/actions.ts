"use server";

import { revalidatePath } from "next/cache";
import { createServiceRoleClient } from "@/lib/supabase";

// Called from a <form action={...}> in the invoices page. Anyone can invoke a server action directly.
export async function deleteInvoice(invoiceId: string) {
  const admin = createServiceRoleClient();
  const { error } = await admin.from("invoices").delete().eq("id", invoiceId);
  if (error) throw new Error("Failed to delete invoice");
  revalidatePath("/invoices");
}
