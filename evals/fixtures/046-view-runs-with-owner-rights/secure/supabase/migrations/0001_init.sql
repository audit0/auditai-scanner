-- Invoices belong to a tenant and RLS keeps tenants apart. A dashboard view sums them and, with
-- security_invoker, runs as the caller: each tenant sees only its own total.
create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references auth.users (id) on delete cascade,
  total numeric(12, 2) not null
);

alter table public.invoices enable row level security;

create policy "invoices: own tenant" on public.invoices
  for select to authenticated
  using (tenant_id = auth.uid());

-- The view runs with the caller's rights, so the policy on invoices applies inside it.
create view public.invoice_totals with (security_invoker = on) as
  select tenant_id, sum(total) as total
  from public.invoices
  group by tenant_id;
