-- Multi-tenant invoicing schema with RLS (the shared two-tenant seed writes tenants, profiles, invoices).
-- profiles.role decides who is an admin: the admin API route and public.is_admin() both read it.
create table public.tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null
);

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  email text not null,
  full_name text,
  role text not null default 'member'
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

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin')
$$;

create policy "profiles: read own" on public.profiles
  for select to authenticated
  using (id = auth.uid() or public.is_admin());

create policy "tenants: read own tenant" on public.tenants
  for select to authenticated
  using (id = public.current_tenant_id());

create policy "invoices: tenant members read" on public.invoices
  for select to authenticated
  using (tenant_id = public.current_tenant_id() or public.is_admin());

-- Users edit their own profile (display name). UPDATE is revoked on the table and granted back on
-- full_name only, so a request that sets role is refused whatever the policy says.
create policy "profiles: update own" on public.profiles
  for update to authenticated
  using (id = auth.uid());

revoke update on public.profiles from authenticated;
grant update (full_name) on public.profiles to authenticated;
