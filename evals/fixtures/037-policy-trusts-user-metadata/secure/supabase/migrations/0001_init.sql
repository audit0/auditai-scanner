-- A notes app with an "admin sees everything" policy. The only difference between the two
-- variants is where the admin claim comes from.
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text not null
);

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id) on delete cascade,
  body text not null,
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
alter table public.notes enable row level security;

create policy "profiles: read own" on public.profiles
  for select to authenticated
  using (id = auth.uid());

create policy "notes: read own" on public.notes
  for select to authenticated
  using (owner_id = auth.uid());

-- app_metadata is written only by the service role, so the caller cannot grant it to themselves.
create policy "notes: admin reads all" on public.notes
  for select to authenticated
  using ((((select auth.jwt()) -> 'app_metadata' ->> 'is_admin'))::boolean);
