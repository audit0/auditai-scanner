import { describe, expect, it } from "vitest";
import { entitlementColumnsIn, roleColumnsIn, scopeColumnsIn } from "./sql-role-source.js";

describe("roleColumnsIn", () => {
  it("reads a comparison with an admin literal inside a query on the caller's row", () => {
    expect(
      roleColumnsIn(
        "select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin')",
      ),
    ).toEqual([{ table: "profiles", column: "role" }]);
  });

  it("reads IN lists, arrays, @> and = any", () => {
    expect(
      roleColumnsIn(
        "select 1 from members m where m.user_id = auth.uid() and m.kind in ('owner', 'viewer')",
      ),
    ).toEqual([{ table: "members", column: "kind" }]);
    expect(
      roleColumnsIn(
        "select coalesce(user_types, array[]::text[]) @> array['admin'] from profiles where id = auth.uid()",
      ),
    ).toEqual([{ table: "profiles", column: "user_types" }]);
    expect(
      roleColumnsIn("select 1 from profiles where id = auth.uid() and 'admin' = any (tags)"),
    ).toEqual([{ table: "profiles", column: "tags" }]);
  });

  it("reads a selected column compared outside the subquery, or a role-named one", () => {
    expect(
      roleColumnsIn("(select account_type from profiles where id = auth.uid()) = 'staff'"),
    ).toEqual([{ table: "profiles", column: "account_type" }]);
    expect(roleColumnsIn("select role from public.profiles where id = auth.uid()")).toEqual([
      { table: "profiles", column: "role" },
    ]);
  });

  it("stays silent without the caller's identity, without a role literal, or on a non-role column", () => {
    expect(roleColumnsIn("select 1 from profiles where role = 'admin'")).toEqual([]);
    expect(
      roleColumnsIn("select 1 from profiles where id = auth.uid() and status = 'active'"),
    ).toEqual([]);
    expect(roleColumnsIn("select full_name from profiles where id = auth.uid()")).toEqual([]);
  });

  it("attributes the column to the query it sits in", () => {
    expect(
      roleColumnsIn(
        "select * from orders o where o.owner_id = auth.uid() or exists (select 1 from profiles p where p.id = auth.uid() and p.role = 'admin')",
      ),
    ).toEqual([{ table: "profiles", column: "role" }]);
  });

  it("survives malformed input", () => {
    expect(roleColumnsIn("select role from")).toEqual([]);
    expect(roleColumnsIn("(select 1 from profiles where id = auth.uid() and role = ")).toEqual([]);
    expect(roleColumnsIn("")).toEqual([]);
  });
});

describe("roleColumnsIn, identity outside the query", () => {
  it("reads auth.uid() in (select id from ... where role = 'admin')", () => {
    expect(
      roleColumnsIn(
        "auth.uid() = teacher_id or auth.uid() in (select id from public.user_profiles where role = 'admin')",
      ),
    ).toEqual([{ table: "user_profiles", column: "role" }]);
  });
});

describe("scopeColumnsIn", () => {
  it("reads the tenant column a query selects from the caller's row, or ties to another row", () => {
    expect(
      scopeColumnsIn("select organisation_id from public.user_profiles where id = auth.uid()"),
    ).toEqual([{ table: "user_profiles", column: "organisation_id" }]);
    expect(
      scopeColumnsIn("org_id in (select m.org_id from members m where m.user_id = auth.uid())"),
    ).toEqual([{ table: "members", column: "org_id" }]);
    expect(
      scopeColumnsIn(
        "exists (select 1 from members m where m.org_id = projects.org_id and m.user_id = auth.uid())",
      ),
    ).toEqual([{ table: "members", column: "org_id" }]);
  });

  it("ignores other columns, queries not about the caller, and malformed input", () => {
    expect(scopeColumnsIn("select full_name from profiles where id = auth.uid()")).toEqual([]);
    expect(scopeColumnsIn("select org_id from projects where id = $1")).toEqual([]);
    expect(scopeColumnsIn("select org_id from")).toEqual([]);
    expect(scopeColumnsIn("")).toEqual([]);
  });
});

describe("entitlementColumnsIn", () => {
  it("reads a comparison inside the query, whatever row it picks", () => {
    expect(
      entitlementColumnsIn(
        "select coalesce((select p.plan = 'plus' from profiles p where p.id = p_uid), false)",
      ),
    ).toEqual([{ table: "profiles", column: "plan" }]);
    expect(
      entitlementColumnsIn(
        "select 1 from wallets where user_id = auth.uid() and balance >= p_cost",
      ),
    ).toEqual([{ table: "wallets", column: "balance" }]);
  });

  it("reads a selected column compared outside the subquery", () => {
    expect(
      entitlementColumnsIn("(select plan from public.tenants where id = p_tenant_id) <> 'free'"),
    ).toEqual([{ table: "tenants", column: "plan" }]);
  });

  it("follows SELECT ... INTO a variable that a later IF or comparison decides on", () => {
    expect(
      entitlementColumnsIn(`
        declare v_credits int;
        begin
          select credits into v_credits from public.profiles where id = p_user_id for update;
          if v_credits <= 0 then raise exception 'Insufficient credits'; end if;
          update public.profiles set credits = credits - 1 where id = p_user_id;
        end`),
    ).toEqual([{ table: "profiles", column: "credits" }]);
    expect(
      entitlementColumnsIn(
        "select is_premium into v_premium from profiles where id = auth.uid(); if not v_premium then raise exception 'x'; end if;",
      ),
    ).toEqual([{ table: "profiles", column: "is_premium" }]);
  });

  it("pairs several selected columns with their INTO variables", () => {
    expect(
      entitlementColumnsIn(`
        select balance, total_used into v_balance, v_used from user_points where user_id = p_user_id for update;
        if v_balance is null then raise exception 'none'; end if;
        if v_balance < p_points_used then raise exception 'insufficient'; end if;`),
    ).toEqual([{ table: "user_points", column: "balance" }]);
  });

  it("reads a CASE that picks a limit by the plan's literal values", () => {
    expect(
      entitlementColumnsIn(`
        if p_plan is null then select plan into v_plan from public.tenants where id = p_tenant_id; end if;
        v_limit := case v_plan when 'free'::plan_t then 1 when 'pro'::plan_t then 3 else 1 end;`),
    ).toEqual([{ table: "tenants", column: "plan" }]);
  });

  it("does not take a null test for a decision", () => {
    expect(
      entitlementColumnsIn(
        "select coalesce(l.tier, 0) into my_tier from league l where l.user_id = auth.uid(); if my_tier is null then my_tier := 0; end if;",
      ),
    ).toEqual([]);
  });

  it("does not count equality with a parameter or another value: a search filter or a join", () => {
    expect(
      entitlementColumnsIn("select p.id from profiles p where (p_plan is null or p.plan = p_plan)"),
    ).toEqual([]);
    expect(
      entitlementColumnsIn(
        "select tier into my_tier from league where user_id = auth.uid(); select * from league l where l.tier = my_tier;",
      ),
    ).toEqual([]);
    expect(
      entitlementColumnsIn("select 1 from profiles p where p.plan in (a.plan, b.plan)"),
    ).toEqual([]);
    expect(
      entitlementColumnsIn("select 1 from profiles p where p.plan in ('pro'::plan_t, 'team')"),
    ).toEqual([{ table: "profiles", column: "plan" }]);
  });

  it("stays silent when the column is only returned, or on other column names", () => {
    expect(
      entitlementColumnsIn(
        "select jsonb_build_object('plan', p.plan, 'credits', p.credits) from profiles p where p.id = auth.uid()",
      ),
    ).toEqual([]);
    expect(
      entitlementColumnsIn(
        "select credits into v_credits from profiles where id = auth.uid(); return v_credits;",
      ),
    ).toEqual([]);
    expect(
      entitlementColumnsIn("select 1 from profiles where id = auth.uid() and name = 'x'"),
    ).toEqual([]);
    expect(entitlementColumnsIn("not sql (((")).toEqual([]);
  });
});
