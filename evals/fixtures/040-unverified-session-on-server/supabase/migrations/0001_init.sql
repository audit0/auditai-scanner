-- One table of per-user rows, protected by Row Level Security. The database side is correct in both
-- variants of this fixture: the difference is entirely in how the application decides who is calling.
create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  item text not null,
  total_cents integer not null default 0,
  created_at timestamptz not null default now()
);

alter table public.orders enable row level security;

create policy "orders are readable by their owner" on public.orders
  for select using (auth.uid() = user_id);

create policy "orders are written by their owner" on public.orders
  for insert with check (auth.uid() = user_id);
