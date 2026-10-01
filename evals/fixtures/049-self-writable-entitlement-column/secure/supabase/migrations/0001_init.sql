-- Multi-tenant invoicing schema with RLS (the shared two-tenant seed writes tenants, profiles, invoices).
-- profiles.credits is what a user may still spend on paid exports: the export route refuses at zero
-- and public.spend_export_credit() takes one away.
create table public.tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null
);

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  email text not null,
  full_name text,
  credits integer not null default 3
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

-- One paid export: refuses at zero, otherwise takes a credit from the caller's own row.
create or replace function public.spend_export_credit()
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_credits integer;
begin
  select credits into v_credits from public.profiles where id = auth.uid() for update;
  if v_credits is null or v_credits <= 0 then
    raise exception 'no export credits left';
  end if;
  update public.profiles set credits = credits - 1 where id = auth.uid();
  return v_credits - 1;
end
$$;

revoke execute on function public.spend_export_credit() from public, anon;
grant execute on function public.spend_export_credit() to authenticated;

create policy "profiles: read own" on public.profiles
  for select to authenticated
  using (id = auth.uid());

create policy "tenants: read own tenant" on public.tenants
  for select to authenticated
  using (id = public.current_tenant_id());

create policy "invoices: tenant members read" on public.invoices
  for select to authenticated
  using (tenant_id = public.current_tenant_id());

-- Users edit their own profile (display name). UPDATE is revoked on the table and granted back on
-- full_name only, so a request that sets credits is refused whatever the policy says;
-- spend_export_credit() still changes them, as the table owner.
create policy "profiles: update own" on public.profiles
  for update to authenticated
  using (id = auth.uid());

revoke update on public.profiles from authenticated;
grant update (full_name) on public.profiles to authenticated;
