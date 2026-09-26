create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text not null unique,
  phone text
);
alter table public.profiles enable row level security;
create policy "profiles: owner reads" on public.profiles for select to authenticated
  using (id = auth.uid());
