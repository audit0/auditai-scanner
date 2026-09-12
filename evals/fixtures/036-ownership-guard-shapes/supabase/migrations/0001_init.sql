-- Multi-tenant project tracker with RLS. The policies are correct; the routes go through the
-- service role and must check ownership themselves.
create table public.tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null
);

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  email text not null
);

create table public.projects (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  owner_id uuid not null references public.profiles (id) on delete cascade,
  name text not null
);

create table public.tasks (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.projects (id) on delete cascade,
  title text not null,
  done boolean not null default false
);

create table public.documents (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles (id) on delete cascade,
  title text not null,
  body text not null default ''
);

create table public.reports (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles (id) on delete cascade,
  title text not null,
  payload jsonb not null default '{}'::jsonb
);

alter table public.tenants enable row level security;
alter table public.profiles enable row level security;
alter table public.projects enable row level security;
alter table public.tasks enable row level security;
alter table public.documents enable row level security;
alter table public.reports enable row level security;

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

create policy "projects: owner reads" on public.projects
  for select to authenticated
  using (owner_id = auth.uid());

create policy "tasks: project owner reads" on public.tasks
  for select to authenticated
  using (project_id in (select id from public.projects where owner_id = auth.uid()));

create policy "documents: owner reads" on public.documents
  for select to authenticated
  using (owner_id = auth.uid());

create policy "reports: owner reads" on public.reports
  for select to authenticated
  using (owner_id = auth.uid());
