-- A public changelog with a subscribe form. Reading is public on purpose; writing is not.
create table public.posts (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  body text not null,
  published boolean not null default true
);

create table public.subscribers (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  created_at timestamptz not null default now()
);

alter table public.posts enable row level security;
alter table public.subscribers enable row level security;

create policy "posts: anyone reads published" on public.posts
  for select to anon, authenticated
  using (published);

-- A public form may insert, but the row still has to look like a subscription: an open
-- `with check (true)` here would be reported as medium ("confirm this is intended").
create policy "subscribers: anyone subscribes" on public.subscribers
  for insert to anon, authenticated
  with check (position('@' in email) > 1 and char_length(email) <= 320);

-- Unsubscribing goes through a one-time token checked server-side, so the Data API needs no
-- delete policy for anon at all; the service role removes the row.
create policy "subscribers: anyone unsubscribes" on public.subscribers
  for delete to authenticated
  using (email = auth.email());
