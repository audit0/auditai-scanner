import { notFound, redirect } from "next/navigation";
import { createAdminClient } from "@/lib/supabase/admin";
import { createServerSupabaseClient } from "@/lib/supabase/server";

// Server component: renders one project. The cookie client checks who is signed in, but the
// row itself is fetched with the admin client, filtered by id only.
export default async function ProjectPage({ params }: { params: Promise<{ id: string }> }) {
  const supabase = await createServerSupabaseClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const { id } = await params;
  const admin = createAdminClient();
  const { data: project } = await admin.from("projects").select("*").eq("id", id).single();
  if (!project) notFound();

  return (
    <main>
      <h1>{project.name}</h1>
      <p>{project.description}</p>
    </main>
  );
}
