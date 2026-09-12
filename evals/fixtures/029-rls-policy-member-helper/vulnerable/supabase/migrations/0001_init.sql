-- Multi-tenant schema with RLS (the shared two-tenant seed writes tenants, profiles, invoices) plus
-- account notes guarded by a membership helper, the shape of real CRM and SaaS repositories.
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

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null references public.tenants (id) on delete cascade,
  author_id uuid not null references public.profiles (id) on delete cascade,
  body text not null
);

alter table public.tenants enable row level security;
alter table public.profiles enable row level security;
alter table public.invoices enable row level security;
alter table public.notes enable row level security;

create or replace function public.current_tenant_id()
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select tenant_id from public.profiles where id = auth.uid()
$$;

-- "Is the caller a member of this account?" The body only checks that the account has members at
-- all; it never compares them with the caller, so every account passes for everyone.
create or replace function public.is_account_member(p_account_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.profiles where tenant_id = p_account_id)
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

create policy "notes: account members read" on public.notes
  for select to authenticated
  using (public.is_account_member(account_id));

create policy "notes: members write their own" on public.notes
  for insert to authenticated
  with check (author_id = auth.uid() and public.is_account_member(account_id));
