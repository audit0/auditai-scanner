"use client";

import { createClient } from "@supabase/supabase-js";
import { useEffect, useState } from "react";

// Anon key in the browser is fine: the signed-in session is attached and RLS decides what is visible.
const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);

export function InvoiceList() {
  const [rows, setRows] = useState<Array<{ id: string; customer_name: string; amount_cents: number }>>([]);
  useEffect(() => {
    supabase
      .from("invoices")
      .select("id, customer_name, amount_cents")
      .then(({ data }) => setRows(data ?? []));
  }, []);
  return (
    <ul>
      {rows.map((r) => (
        <li key={r.id}>
          {r.customer_name}: {(r.amount_cents / 100).toFixed(2)}
        </li>
      ))}
    </ul>
  );
}
