"use server";

import { revalidatePath } from "next/cache";
import { enhanceAction } from "@/lib/actions/enhance";
import { removeInvoice } from "@/lib/invoices";

// Tenant scope comes from the authenticated user's app_metadata (server-controlled), never from data.
export const deleteInvoice = enhanceAction(async (data: { id: string }, user) => {
  const tenantId = user.app_metadata.tenant_id;
  if (!tenantId) throw new Error("Forbidden");
  await removeInvoice(data.id, tenantId);
  revalidatePath("/invoices");
  return { ok: true };
});
