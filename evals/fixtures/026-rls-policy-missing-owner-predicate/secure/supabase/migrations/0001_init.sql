-- Project workspace schema. RLS is enabled on both tables and the projects policy is scoped.
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text not null
);

create table public.projects (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles (id) on delete cascade,
  name text not null,
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
alter table public.projects enable row level security;

create policy "profiles: read own" on public.profiles
  for select to authenticated
  using (id = auth.uid());

create policy "projects: owner can read" on public.projects
  for select to authenticated
  using (owner_id = auth.uid());

create policy "projects: owner can insert" on public.projects
  for insert to authenticated
  with check (owner_id = auth.uid());
