-- Multi-tenant invoicing schema with RLS (the shared two-tenant seed writes tenants, profiles, invoices).
-- public.user_roles.role decides who is an admin: the admin API route and public.is_admin() read it.
-- Nobody edits it through the API; public.handle_new_user() writes it once, at sign-up.
create table public.tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null
);

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  email text not null
);

create table public.user_roles (
  user_id uuid primary key references auth.users (id) on delete cascade,
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
alter table public.user_roles enable row level security;
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
  select exists (select 1 from public.user_roles where user_id = auth.uid() and role = 'admin')
$$;

create policy "profiles: read own" on public.profiles
  for select to authenticated
  using (id = auth.uid() or public.is_admin());

create policy "user_roles: read own" on public.user_roles
  for select to authenticated
  using (user_id = auth.uid());

create policy "tenants: read own tenant" on public.tenants
  for select to authenticated
  using (id = public.current_tenant_id());

create policy "invoices: tenant members read" on public.invoices
  for select to authenticated
  using (tenant_id = public.current_tenant_id() or public.is_admin());

-- Sign-up. The role comes from what the client passed in signUp({ options: { data: { role } } }),
-- defaulting to member: anyone who passes role = 'admin' is created as an admin.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.user_roles (user_id, role)
  values (new.id, coalesce(new.raw_user_meta_data ->> 'role', 'member'));
  return new;
end
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();
