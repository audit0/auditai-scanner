-- Invoices belong to a tenant and RLS keeps tenants apart. A dashboard view sums them; created the
-- default way, it runs with its owner's rights (postgres), whom RLS does not bind, so anyone who may
-- select the view reads every tenant's totals. Supabase's linter calls the shape 0010.
create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references auth.users (id) on delete cascade,
  total numeric(12, 2) not null
);

alter table public.invoices enable row level security;

create policy "invoices: own tenant" on public.invoices
  for select to authenticated
  using (tenant_id = auth.uid());

-- Missing: with (security_invoker = on)
create view public.invoice_totals as
  select tenant_id, sum(total) as total
  from public.invoices
  group by tenant_id;
