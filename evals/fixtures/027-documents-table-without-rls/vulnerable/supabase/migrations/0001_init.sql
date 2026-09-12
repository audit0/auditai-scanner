-- Document storage schema. profiles has RLS; documents does not (the "TODO before launch" that
-- never happened).
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

create policy "profiles: read own" on public.profiles
  for select to authenticated
  using (id = auth.uid());

-- TODO: add RLS to documents before launch
