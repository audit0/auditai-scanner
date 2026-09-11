import { deleteInvoice } from "@/app/actions";
import { createUserClient } from "@/lib/supabase-server";

export default async function InvoicesPage() {
  const supabase = await createUserClient();
  const { data } = await supabase.from("invoices").select("id, customer_name").limit(50);
  return (
    <main>
      <h1>Invoices</h1>
      <ul>
        {(data ?? []).map((inv) => (
          <li key={inv.id}>
            {inv.customer_name}
            <form action={deleteInvoice.bind(null, inv.id)}>
              <button type="submit">Delete</button>
            </form>
          </li>
        ))}
      </ul>
    </main>
  );
}
