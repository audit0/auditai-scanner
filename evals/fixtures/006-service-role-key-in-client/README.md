# Fixture 006: service-role key in a client component

A client component creates a Supabase client with `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`. The `NEXT_PUBLIC_` prefix inlines the value into the JavaScript bundle, so every visitor can copy the key from DevTools and read or delete every row in every table. RLS is irrelevant: the service role bypasses it.

- `vulnerable/`: service-role key in `"use client"` code and in `.env.example` under a public name.
- `secure/`: anon key; RLS decides visibility.
