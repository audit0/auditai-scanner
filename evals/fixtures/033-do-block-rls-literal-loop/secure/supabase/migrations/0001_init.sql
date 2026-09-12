-- Multi-tenant notes. RLS is switched on for a list of tables inside a DO block; the list is complete.
create table public.tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null
);

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  email text not null
);

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  owner_id uuid not null references public.profiles (id) on delete cascade,
  body text not null,
  created_at timestamptz not null default now()
);

create table public.notes_archive (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  owner_id uuid not null references public.profiles (id) on delete cascade,
  body text not null,
  archived_at timestamptz not null default now()
);

alter table public.tenants enable row level security;
alter table public.profiles enable row level security;

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

-- Tenant isolation for every content table, applied in one loop over a literal list.
do $$
declare
  t text;
begin
  foreach t in array array['notes', 'notes_archive'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('drop policy if exists tenant_isolation_%s on public.%I', t, t);
    execute format(
      'create policy tenant_isolation_%s on public.%I for select to authenticated
         using (tenant_id = public.current_tenant_id())',
      t, t
    );
    execute format('revoke all on public.%I from anon', t);
  end loop;
end
$$;
