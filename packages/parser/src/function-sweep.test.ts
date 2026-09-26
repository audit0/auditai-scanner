import { describe, expect, it } from "vitest";
import type { RlsTable } from "./model.js";
import { parseSqlForRls, sqlSchemaFor } from "./rls.js";

/**
 * A hardening migration that revokes EXECUTE on every SECURITY DEFINER function of a schema with a
 * loop over pg_proc (fifth blind sample: seven critical false positives in one repository). The loop
 * is run against the functions the model knows at that point; only the exact catalog shape counts,
 * and anything the parser cannot evaluate leaves the grants as they were.
 */

function parse(...files: string[]) {
  const tables = new Map<string, RlsTable>();
  files.forEach((sql, i) => {
    parseSqlForRls(`supabase/migrations/${String(i).padStart(3, "0")}_m.sql`, sql, tables);
  });
  return sqlSchemaFor(tables);
}

const grantedTo = (sql: ReturnType<typeof parse>, name: string): string[] | undefined =>
  sql.sqlFunctions?.find((f) => f.name === name)?.grantedTo;

const DEFINER = (
  name: string,
  args = "p_id uuid",
) => `create or replace function public.${name}(${args})
returns int language sql security definer set search_path = public as $$ select 1 $$;`;

const loop = (where: string, body?: string) => `do $$
declare fn record;
begin
  for fn in
    select p.oid::regprocedure as regproc
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where ${where}
  loop
    ${
      body ??
      `execute format('revoke all privileges on function %s from public', fn.regproc);
    execute format('revoke all privileges on function %s from anon', fn.regproc);
    execute format('revoke all privileges on function %s from authenticated', fn.regproc);
    execute format('grant execute on function %s to service_role', fn.regproc);`
    }
  end loop;
end $$;`;

const SWEEP = loop("n.nspname = 'public' and p.prosecdef");

const openToApi = (g: string[] | undefined) =>
  (g ?? []).some((r) => r === "anon" || r === "authenticated" || r === "public");

describe("a REVOKE loop over every SECURITY DEFINER function of a schema", () => {
  it("revokes from the API roles every definer function defined before it", () => {
    const sql = parse(DEFINER("get_stats"), SWEEP);
    expect(openToApi(grantedTo(sql, "get_stats"))).toBe(false);
    expect(grantedTo(sql, "get_stats")).toContain("service_role");
  });

  it("leaves a definer function created after it with the default grants", () => {
    const sql = parse(SWEEP, DEFINER("later_fn"));
    expect(openToApi(grantedTo(sql, "later_fn"))).toBe(true);
  });

  it("keeps the revoke through CREATE OR REPLACE with the same argument types", () => {
    const sql = parse(DEFINER("get_stats", "p_id uuid"), SWEEP, DEFINER("get_stats", "p_id UUID"));
    expect(openToApi(grantedTo(sql, "get_stats"))).toBe(false);
  });

  it("gives a new overload (other argument types) the default grants again", () => {
    const sql = parse(
      DEFINER("get_stats", "p_id uuid"),
      SWEEP,
      DEFINER("get_stats", "p_n integer"),
    );
    expect(openToApi(grantedTo(sql, "get_stats"))).toBe(true);
  });

  it("does not touch functions of another schema than the loop names", () => {
    const sql = parse(DEFINER("get_stats"), loop("n.nspname = 'private' and p.prosecdef"));
    expect(openToApi(grantedTo(sql, "get_stats"))).toBe(true);
  });

  it("does not touch invoker functions", () => {
    const invoker = `create function public.plain() returns int language sql as $$ select 1 $$;`;
    const sql = parse(invoker, SWEEP);
    expect(openToApi(grantedTo(sql, "plain"))).toBe(true);
  });

  it("follows the loop only in its exact shape", () => {
    for (const where of [
      "n.nspname = 'public' and p.prosecdef and p.proname like 'admin_%'",
      "n.nspname = 'public' and p.prosecdef and p.proname <> 'get_stats'",
      "n.nspname = 'public' and p.prosecdef and not p.proisstrict",
      "n.nspname = 'public' or p.prosecdef",
      "n.nspname = 'public'",
      "p.prosecdef",
    ]) {
      const sql = parse(DEFINER("get_stats"), loop(where));
      expect(openToApi(grantedTo(sql, "get_stats")), where).toBe(true);
    }
  });

  it("does not follow a loop whose body does anything but grant or revoke", () => {
    const body = `execute format('revoke all on function %s from anon', fn.regproc);
    execute format('alter function %s owner to postgres', fn.regproc);`;
    const sql = parse(DEFINER("get_stats"), loop("n.nspname = 'public' and p.prosecdef", body));
    expect(grantedTo(sql, "get_stats")).toContain("anon");
  });

  it("does not follow the loop under an IF", () => {
    const guarded = `do $$
declare fn record;
begin
  if current_setting('app.harden', true) = 'on' then
    for fn in select p.oid::regprocedure as regproc from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.prosecdef
    loop
      execute format('revoke all on function %s from anon, authenticated, public', fn.regproc);
    end loop;
  end if;
end $$;`;
    const sql = parse(DEFINER("get_stats"), guarded);
    expect(openToApi(grantedTo(sql, "get_stats"))).toBe(true);
  });

  it("does not follow a block with an exception handler, which may swallow a failed revoke", () => {
    const withHandler = SWEEP.replace(
      "end $$;",
      "exception when others then raise notice 'skipped';\nend $$;",
    );
    const sql = parse(DEFINER("get_stats"), withHandler);
    expect(openToApi(grantedTo(sql, "get_stats"))).toBe(true);
  });

  it("applies a later explicit GRANT on top of the loop", () => {
    const regrant = `grant execute on function public.get_stats(uuid) to authenticated;`;
    const sql = parse(DEFINER("get_stats"), SWEEP, regrant);
    expect(grantedTo(sql, "get_stats")).toContain("authenticated");
  });

  // Review of 23 September 2026 (scratchpad verify-gap1).
  it("does not sweep a function from SQL run by hand, whose place in the history is unknown (c01)", () => {
    for (const handRun of [
      "supabase/migrations/add_invite_lookup.sql",
      "supabase/sql/invite_lookup.sql",
      "database/functions.sql",
    ]) {
      const tables = new Map<string, RlsTable>();
      parseSqlForRls(handRun, DEFINER("find_profile"), tables);
      parseSqlForRls("supabase/migrations/002_harden.sql", SWEEP, tables);
      expect(openToApi(grantedTo(sqlSchemaFor(tables), "find_profile")), handRun).toBe(true);
    }
  });

  it("does not run a loop that is itself in SQL run by hand", () => {
    const tables = new Map<string, RlsTable>();
    parseSqlForRls("supabase/migrations/001_init.sql", DEFINER("get_stats"), tables);
    parseSqlForRls("supabase/sql/harden.sql", SWEEP, tables);
    expect(openToApi(grantedTo(sqlSchemaFor(tables), "get_stats"))).toBe(true);
  });

  it("does not follow a loop whose ON clause filters functions (c02)", () => {
    const onFilter = SWEEP.replace(
      "join pg_namespace n on n.oid = p.pronamespace",
      "join pg_namespace n on n.oid = p.pronamespace and p.proname <> 'get_stats'",
    );
    const sql = parse(DEFINER("get_stats"), onFilter);
    expect(openToApi(grantedTo(sql, "get_stats"))).toBe(true);
  });

  it("does not follow a second pg_proc in FROM (c13)", () => {
    const twice = SWEEP.replace(
      "join pg_namespace n on n.oid = p.pronamespace",
      "join pg_namespace n on n.oid = p.pronamespace join pg_proc q on q.oid = p.oid",
    );
    const sql = parse(DEFINER("get_stats"), twice);
    expect(openToApi(grantedTo(sql, "get_stats"))).toBe(true);
  });

  it("compares the schema literal case-sensitively, as Postgres does (c05)", () => {
    const sql = parse(DEFINER("get_stats"), loop("n.nspname = 'Public' and p.prosecdef"));
    expect(openToApi(grantedTo(sql, "get_stats"))).toBe(true);
  });

  it("does not follow a body that reads another field or the whole record (l06, l13)", () => {
    for (const body of [
      "execute format('revoke all on function %s from anon, authenticated, public', fn.nope);",
      "execute format('revoke all on function %s from anon, authenticated, public', fn);",
    ]) {
      const sql = parse(DEFINER("get_stats"), loop("n.nspname = 'public' and p.prosecdef", body));
      expect(openToApi(grantedTo(sql, "get_stats")), body).toBe(true);
    }
  });

  it("does not follow a body that raises an exception (l08)", () => {
    const body = `execute format('revoke all on function %s from anon, authenticated, public', fn.regproc);
    raise exception 'stop';`;
    const sql = parse(DEFINER("get_stats"), loop("n.nspname = 'public' and p.prosecdef", body));
    expect(openToApi(grantedTo(sql, "get_stats"))).toBe(true);
  });

  it("follows a body with a notice", () => {
    const body = `raise notice 'revoking %', fn.regproc;
    execute format('revoke all on function %s from anon, authenticated, public', fn.regproc);`;
    const sql = parse(DEFINER("get_stats"), loop("n.nspname = 'public' and p.prosecdef", body));
    expect(openToApi(grantedTo(sql, "get_stats"))).toBe(false);
  });
});

describe("a block that does more than the loop is not followed (second review)", () => {
  const LOOP_ONLY = `  for fn in
    select p.oid::regprocedure as regproc
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.prosecdef
  loop
    execute format('revoke all on function %s from public, anon, authenticated', fn.regproc);
  end loop;`;
  const block = (after: string) =>
    `do $$\ndeclare fn record;\nbegin\n${LOOP_ONLY}\n  ${after}\nend $$;`;
  for (const [name, after] of [
    [
      "t05: a plain GRANT after the loop",
      "grant execute on function public.get_stats(uuid) to authenticated;",
    ],
    [
      "t14: the GRANT in a nested block",
      "begin grant execute on function public.get_stats(uuid) to authenticated; end;",
    ],
    [
      "t20: the GRANT under an IF",
      "if true then grant execute on function public.get_stats(uuid) to authenticated; end if;",
    ],
    [
      "t21: GRANT on all functions in the schema",
      "grant execute on all functions in schema public to authenticated;",
    ],
    [
      "t26: DROP and CREATE after the loop",
      "drop function public.get_stats(uuid); create function public.get_stats(p_id uuid) returns int language sql security definer as 'select 1';",
    ],
  ] as const) {
    it(name, () => {
      const sql = parse(DEFINER("get_stats"), block(after));
      expect(openToApi(grantedTo(sql, "get_stats"))).toBe(true);
    });
  }

  it("twin: the loop with only a notice after it is followed", () => {
    const sql = parse(DEFINER("get_stats"), block("raise notice 'hardened';"));
    expect(openToApi(grantedTo(sql, "get_stats"))).toBe(false);
  });

  it("t09: a loop in another migrations folder (another database) does not reach the function", () => {
    const tables = new Map<string, RlsTable>();
    parseSqlForRls("apps/customer/supabase/migrations/001_fn.sql", DEFINER("get_stats"), tables);
    parseSqlForRls("apps/internal/supabase/migrations/002_harden.sql", SWEEP, tables);
    expect(openToApi(grantedTo(sqlSchemaFor(tables), "get_stats"))).toBe(true);
  });
});

describe("CREATE OR REPLACE keeps the privileges of the same signature", () => {
  const REVOKE = (sig: string) =>
    `revoke execute on function public.f(${sig}) from public, anon, authenticated;`;
  const FN = (args: string) =>
    `create or replace function public.f(${args}) returns int language sql security definer as $$ select 1 $$;`;
  for (const [first, again] of [
    ["p varchar(255)", "p varchar"],
    ["p numeric(10,2)", "p numeric"],
    ["p character varying(20)", "p varchar"],
    ["p int[]", "p integer[]"],
    ["p decimal", "p numeric"],
    ["p float", "p double precision"],
    ["p extensions.citext", "p citext"],
    ["p char(1)", "p character(1)"],
  ] as const) {
    it(`${first} then ${again}`, () => {
      const sql = parse(FN(first), REVOKE(first.slice(2)), FN(again));
      expect(openToApi(grantedTo(sql, "f"))).toBe(false);
    });
  }
});

describe("third review: CREATE OR REPLACE in `supabase db diff` form, and GRANTs inside DO blocks", () => {
  const HAND = `create function public.find_profile(p_email text) returns int language sql security definer as $$ select 1 $$;`;
  const REVOKE = `revoke all on function public.find_profile(text) from public, anon, authenticated;`;
  for (const [name, diff] of [
    [
      "quoted name and type",
      `CREATE OR REPLACE FUNCTION "public"."find_profile"("p_email" "text") RETURNS integer LANGUAGE "sql" SECURITY DEFINER AS $$ select 1 $$;`,
    ],
    [
      "quoted, with a default",
      `CREATE OR REPLACE FUNCTION "public"."find_profile"("p_email" "text" DEFAULT NULL::"text") RETURNS integer LANGUAGE "sql" SECURITY DEFINER AS $$ select 1 $$;`,
    ],
    [
      "= null default",
      `create or replace function public.find_profile(p_email text = null) returns int language sql security definer as $$ select 1 $$;`,
    ],
  ] as const) {
    it(`keeps the revoke through a replace with the same signature: ${name}`, () => {
      const sql = parse(HAND, REVOKE, diff);
      expect(openToApi(grantedTo(sql, "find_profile"))).toBe(false);
    });
  }

  for (const [name, block] of [
    [
      "t29: a GRANT under IF in a later migration",
      `do $$ begin if exists (select 1 from pg_roles where rolname = 'authenticated') then grant execute on function public.get_stats(uuid) to authenticated; end if; end $$;`,
    ],
    [
      "a01: a plain GRANT in a DO block",
      `do $$ begin grant execute on function public.get_stats(uuid) to anon; end $$;`,
    ],
    [
      "a02: a GRANT guarded by an exception handler",
      `do $$ begin grant execute on function public.get_stats(uuid) to authenticated; exception when undefined_function then null; end $$;`,
    ],
    [
      "a08: GRANT ON ALL FUNCTIONS in a DO block",
      `do $$ begin grant execute on all functions in schema public to authenticated; end $$;`,
    ],
  ] as const) {
    it(`reads a later re-grant: ${name}`, () => {
      const sql = parse(DEFINER("get_stats"), SWEEP, block);
      expect(openToApi(grantedTo(sql, "get_stats"))).toBe(true);
    });
  }
});
