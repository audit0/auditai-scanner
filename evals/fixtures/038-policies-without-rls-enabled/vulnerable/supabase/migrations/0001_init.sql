-- A team wiki. The migration writes careful policies for both tables; only one of them ever gets
-- row level security switched on.
create table public.workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null
);

create table public.members (
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  primary key (workspace_id, user_id)
);

create table public.pages (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  title text not null,
  body text not null
);

alter table public.workspaces enable row level security;
alter table public.members enable row level security;
-- Missing: alter table public.pages enable row level security;

create policy "workspaces: members read" on public.workspaces
  for select to authenticated
  using (exists (select 1 from public.members m where m.workspace_id = id and m.user_id = auth.uid()));

create policy "members: read own rows" on public.members
  for select to authenticated
  using (user_id = auth.uid());

create policy "pages: members read" on public.pages
  for select to authenticated
  using (exists (select 1 from public.members m where m.workspace_id = pages.workspace_id and m.user_id = auth.uid()));

create policy "pages: members write" on public.pages
  for insert to authenticated
  with check (exists (select 1 from public.members m where m.workspace_id = pages.workspace_id and m.user_id = auth.uid()));
