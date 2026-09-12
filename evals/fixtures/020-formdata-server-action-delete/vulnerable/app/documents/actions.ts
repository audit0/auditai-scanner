"use server";

import { revalidatePath } from "next/cache";
import { createServiceRoleClient } from "@/lib/supabase";
import { createUserClient } from "@/lib/supabase-server";

// Bound to <form action={deleteDocument}>. The wrapping <form> reads `<input name="id">`, so the
// id arrives as a FormData entry rather than a plain argument — this is the standard shape for a
// server action invoked directly from a <form>, as opposed to one called with .bind() (fixture 009)
// or invoked programmatically with a plain object (fixture 012).
//
// The caller is authenticated (the cookie client's auth.getUser() must succeed), but the delete
// itself runs with the service-role client and is scoped by id only: any signed-in user can
// delete any tenant's document by submitting its id.
export async function deleteDocument(formData: FormData) {
  const supabase = await createUserClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) throw new Error("Unauthorized");

  const id = formData.get("id") as string;
  const admin = createServiceRoleClient();
  const { error } = await admin.from("documents").delete().eq("id", id);
  if (error) throw new Error("Failed to delete document");
  revalidatePath("/documents");
}
