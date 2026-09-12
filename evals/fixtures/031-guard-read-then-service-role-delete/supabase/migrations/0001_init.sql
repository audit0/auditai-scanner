-- Multi-tenant flow builder with RLS. The policies are correct; the bug is in the delete route.
create table public.tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null
);

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  email text not null
);

create table public.flows (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  name text not null,
  status text not null default 'draft',
  created_at timestamptz not null default now()
);

alter table public.tenants enable row level security;
alter table public.profiles enable row level security;
alter table public.flows enable row level security;

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

create policy "flows: tenant members read" on public.flows
  for select to authenticated
  using (tenant_id = public.current_tenant_id());

create policy "flows: tenant members insert" on public.flows
  for insert to authenticated
  with check (tenant_id = public.current_tenant_id());

-- Deleting is reserved for tenant admins in the full app; the API route goes around this policy
-- with the service role, which is exactly why it must check ownership itself.
create policy "flows: nobody deletes through the API" on public.flows
  for delete to authenticated
  using (false);
