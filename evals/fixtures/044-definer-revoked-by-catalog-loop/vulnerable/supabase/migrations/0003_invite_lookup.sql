-- Looks a person up by email address for the invite form.
create or replace function public.find_profile_by_email(p_email text)
returns table (id uuid, phone text)
language sql
security definer
set search_path = public
as $$
  select id, phone from public.profiles where email = p_email;
$$;
