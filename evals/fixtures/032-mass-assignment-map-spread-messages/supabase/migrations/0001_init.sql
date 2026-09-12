-- Chat schema with RLS. The policies are correct; the bug is in the message route.
create table public.chats (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  title text not null default 'New chat',
  created_at timestamptz not null default now()
);

create table public.messages (
  id uuid primary key default gen_random_uuid(),
  chat_id uuid not null references public.chats (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  role text not null check (role in ('user', 'assistant')),
  content text not null,
  pinned boolean not null default false,
  cost_cents integer not null default 0,
  created_at timestamptz not null default now()
);

alter table public.chats enable row level security;
alter table public.messages enable row level security;

create policy "chats: owner reads" on public.chats
  for select to authenticated
  using (user_id = auth.uid());

create policy "chats: owner inserts" on public.chats
  for insert to authenticated
  with check (user_id = auth.uid());

create policy "messages: owner reads" on public.messages
  for select to authenticated
  using (user_id = auth.uid());
