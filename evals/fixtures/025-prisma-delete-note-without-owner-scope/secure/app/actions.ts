"use server";

import { revalidatePath } from "next/cache";
import { prisma } from "@/lib/prisma";
import { getCurrentUser } from "@/lib/supabase-server";

// Called from a delete button on the notes page. The delete is scoped to the caller's own notes.
export async function deleteNote(id: string) {
  const user = await getCurrentUser();
  if (!user) throw new Error("Unauthorized");

  const result = await prisma.note.deleteMany({ where: { id, userId: user.id } });
  if (result.count === 0) throw new Error("Not found");
  revalidatePath("/notes");
}
