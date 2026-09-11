"use server";

import { revalidatePath } from "next/cache";
import { enhanceAction } from "@/lib/actions/enhance";
import { removeInvoice } from "@/lib/invoices";

// The wrapper authenticates the caller, but the action never checks that the invoice is theirs.
export const deleteInvoice = enhanceAction(async (data: { id: string }) => {
  await removeInvoice(data.id);
  revalidatePath("/invoices");
  return { ok: true };
});
