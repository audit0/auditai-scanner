-- Multi-tenant invoicing schema with RLS (the shared two-tenant seed writes tenants, profiles, invoices).
-- The table policies are correct; the read path goes around them through a SECURITY DEFINER function.
create table public.tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null
);

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  email text not null
);

create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  owner_id uuid not null references public.profiles (id) on delete cascade,
  customer_name text not null,
  amount_cents integer not null check (amount_cents >= 0),
  created_at timestamptz not null default now()
);

alter table public.tenants enable row level security;
alter table public.profiles enable row level security;
alter table public.invoices enable row level security;

create or replace function public.current_tenant_id()
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select tenant_id from public.profiles where id = auth.uid()
$$;

create policy "profiles: read own" on public.profiles
  for select to authenticated
  using (id = auth.uid());

create policy "tenants: read own tenant" on public.tenants
  for select to authenticated
  using (id = public.current_tenant_id());

create policy "invoices: tenant members read" on public.invoices
  for select to authenticated
  using (tenant_id = public.current_tenant_id());

create policy "invoices: tenant members insert" on public.invoices
  for insert to authenticated
  with check (tenant_id = public.current_tenant_id() and owner_id = auth.uid());

-- "RLS kept returning nothing, so the lookup runs as the owner": SECURITY DEFINER skips the invoice
-- policies, and the body filters by the id the caller sends without asking who the caller is.
create or replace function public.get_invoice(invoice_id uuid)
returns setof public.invoices
language sql
stable
security definer
set search_path = ''
as $$
  select * from public.invoices where id = invoice_id
$$;

revoke execute on function public.get_invoice(uuid) from public, anon;
grant execute on function public.get_invoice(uuid) to authenticated;
