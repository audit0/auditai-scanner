"use server";

import { revalidatePath } from "next/cache";
import { prisma } from "@/lib/prisma";
import { getCurrentUser } from "@/lib/supabase-server";

// Called from a delete button on the notes page. Prisma queries Postgres directly, so nothing
// checks that the note belongs to the caller.
export async function deleteNote(id: string) {
  const user = await getCurrentUser();
  if (!user) throw new Error("Unauthorized");

  await prisma.note.delete({ where: { id } });
  revalidatePath("/notes");
}
