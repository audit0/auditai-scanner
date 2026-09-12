-- Document storage schema. RLS is enabled on both tables with owner-scoped policies.
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text not null
);

create table public.documents (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles (id) on delete cascade,
  title text not null,
  body text not null,
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
alter table public.documents enable row level security;

create policy "profiles: read own" on public.profiles
  for select to authenticated
  using (id = auth.uid());

create policy "documents: owner can read" on public.documents
  for select to authenticated
  using (owner_id = auth.uid());

create policy "documents: owner can insert" on public.documents
  for insert to authenticated
  with check (owner_id = auth.uid());
