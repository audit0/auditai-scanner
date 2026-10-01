import { describe, expect, it } from "vitest";
import type { RlsTable } from "./model.js";
import { parseSqlForRls } from "./rls.js";

function tables(sql: string): Map<string, RlsTable> {
  const into = new Map<string, RlsTable>();
  parseSqlForRls("supabase/migrations/20260101000000_init.sql", sql, into);
  return into;
}

const PROFILES = "create table public.profiles (id uuid primary key, full_name text, role text);\n";

describe("table privileges of authenticated", () => {
  it("starts with Supabase's default: every column writable", () => {
    expect(tables(PROFILES).get("profiles")?.authenticatedWrites).toBeUndefined();
  });

  it("narrows to the columns granted back after a table REVOKE", () => {
    const t = tables(
      `${PROFILES}revoke update on public.profiles from authenticated;
grant update (full_name) on public.profiles to authenticated;`,
    ).get("profiles");
    expect(t?.authenticatedWrites).toEqual({ update: ["full_name"] });
  });

  it("ignores a column REVOKE while the table privilege stands, and a REVOKE from PUBLIC only", () => {
    const t = tables(
      `${PROFILES}revoke update (role) on public.profiles from authenticated;
revoke all on public.profiles from public;`,
    ).get("profiles");
    expect(t?.authenticatedWrites).toBeUndefined();
  });

  it("reads REVOKE ALL, ALL TABLES IN SCHEMA and a later GRANT that restores everything", () => {
    const revoked = tables(
      `${PROFILES}revoke all on all tables in schema public from anon, authenticated;`,
    );
    expect(revoked.get("profiles")?.authenticatedWrites).toEqual({ update: [], insert: [] });
    const restored = tables(
      `${PROFILES}revoke all privileges on table profiles from authenticated;
grant select, update on profiles to authenticated;`,
    );
    expect(restored.get("profiles")?.authenticatedWrites).toEqual({ insert: [] });
  });

  it("leaves functions and sequences alone and survives malformed input", () => {
    const t = tables(
      `${PROFILES}revoke execute on function public.f() from authenticated;
revoke usage on sequence profiles_id_seq from authenticated;
revoke update on from authenticated;
grant update (`,
    ).get("profiles");
    expect(t?.authenticatedWrites).toBeUndefined();
  });

  it("remembers policies an ALTER POLICY changed until they are dropped", () => {
    const sql = `${PROFILES}create policy own on profiles for update using (id = auth.uid());
alter policy own on public.profiles using (id = auth.uid()) with check (role = 'member');`;
    expect(tables(sql).get("profiles")?.alteredPolicies).toEqual(["own"]);
    expect(
      tables(`${sql}\ndrop policy own on profiles;`).get("profiles")?.alteredPolicies,
    ).toBeUndefined();
  });
});
