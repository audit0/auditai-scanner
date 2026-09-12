import { createUserClient } from "@/lib/supabase-server";
import { deleteDocument } from "./actions";

export default async function DocumentsPage() {
  const supabase = await createUserClient();
  const { data } = await supabase.from("documents").select("id, title").limit(50);
  return (
    <main>
      <h1>Documents</h1>
      <ul>
        {(data ?? []).map((doc) => (
          <li key={doc.id}>
            {doc.title}
            <form action={deleteDocument}>
              <input type="hidden" name="id" value={doc.id} />
              <button type="submit">Delete</button>
            </form>
          </li>
        ))}
      </ul>
    </main>
  );
}
