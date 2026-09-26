create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text not null unique,
  phone text
);
alter table public.profiles enable row level security;
create policy "profiles: owner reads" on public.profiles for select to authenticated
  using (id = auth.uid());

-- Looks a person up by email address for the invite form.
create or replace function public.find_profile_by_email(p_email text)
returns table (id uuid, phone text)
language sql
security definer
set search_path = public
as $$
  select id, phone from public.profiles where email = p_email;
$$;
