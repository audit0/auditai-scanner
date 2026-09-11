/**
 * Seeds two tenants, two users and one invoice each. Run against a local Supabase only.
 * Uses the service-role key on purpose: seeding is an admin operation, never an app path.
 */
import { createClient } from "@supabase/supabase-js";

const url = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
if (!serviceKey) throw new Error("SUPABASE_SERVICE_ROLE_KEY is required for seeding");

const admin = createClient(url, serviceKey, { auth: { persistSession: false } });

export const FIXTURE_USERS = {
  alice: { email: "alice@tenant-a.test", password: "alice-password-123", tenant: "Tenant A" },
  bob: { email: "bob@tenant-b.test", password: "bob-password-123", tenant: "Tenant B" },
} as const;

async function main(): Promise<void> {
  const ids: Record<string, { userId: string; tenantId: string; invoiceId: string }> = {};
  for (const [key, u] of Object.entries(FIXTURE_USERS)) {
    const { data: tenant, error: tErr } = await admin
      .from("tenants")
      .insert({ name: u.tenant })
      .select("id")
      .single();
    if (tErr) throw tErr;
    const { data: user, error: uErr } = await admin.auth.admin.createUser({
      email: u.email,
      password: u.password,
      email_confirm: true,
    });
    if (uErr) throw uErr;
    const { error: pErr } = await admin
      .from("profiles")
      .insert({ id: user.user.id, tenant_id: tenant.id, email: u.email });
    if (pErr) throw pErr;
    const { data: invoice, error: iErr } = await admin
      .from("invoices")
      .insert({
        tenant_id: tenant.id,
        owner_id: user.user.id,
        customer_name: `${u.tenant} customer`,
        amount_cents: 12500,
      })
      .select("id")
      .single();
    if (iErr) throw iErr;
    ids[key] = { userId: user.user.id, tenantId: tenant.id, invoiceId: invoice.id };
  }
  console.log(JSON.stringify(ids, null, 2));
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
