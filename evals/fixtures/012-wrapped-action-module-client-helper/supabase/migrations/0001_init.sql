-- Two tenants, one invoice each. RLS is enabled and correct; the bug is in the server code.
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
  amount_cents integer not null,
  status text not null default 'open',
  created_at timestamptz not null default now()
);

alter table public.tenants enable row level security;
alter table public.profiles enable row level security;
alter table public.invoices enable row level security;

create policy "profiles: read own" on public.profiles
  for select using (id = auth.uid());

create policy "tenants: read own tenant" on public.tenants
  for select using (id = (select tenant_id from public.profiles where id = auth.uid()));

create policy "invoices: tenant members read" on public.invoices
  for select using (tenant_id = (select tenant_id from public.profiles where id = auth.uid()));

create policy "invoices: tenant members delete" on public.invoices
  for delete using (tenant_id = (select tenant_id from public.profiles where id = auth.uid()));
