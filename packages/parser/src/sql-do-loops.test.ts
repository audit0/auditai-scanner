import { describe, expect, it } from "vitest";
import { expandDoBlock } from "./sql-do-loops.js";
import { splitSqlStatements } from "./sql-lexer.js";

/**
 * Unrolling a DO block. The signature-lookup case is the one that matters most in the wild: a REVOKE
 * sweep over a literal list of function names, wrapped in a `pg_proc` lookup to get each signature.
 * Before 20 September 2026 the nested loop made the whole block dynamic, so every grant it removed
 * stayed in the model and 23 findings of one project were raised against functions nobody could call
 * (docs/realworld/2026-09-20-round-8-plan.md).
 */

const expand = (sql: string) => {
  const stmt = splitSqlStatements(sql)[0];
  if (!stmt) throw new Error("no statement");
  return expandDoBlock(stmt);
};

const sweep = (where: string, body: string): string => `do $$
declare
  fn text;
  sig text;
  names text[] := array['alpha', 'beta'];
begin
  foreach fn in array names loop
    for sig in
      select format('public.%I(%s)', p.proname, pg_get_function_identity_arguments(p.oid))
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where ${where}
    loop
      ${body}
    end loop;
  end loop;
end $$;`;

const NAMED = "n.nspname = 'public' and p.proname = fn and p.prosecdef";

describe("expandDoBlock", () => {
  it("unrolls a revoke sweep written as a signature lookup around a literal list", () => {
    const out = expand(
      sweep(
        NAMED,
        `execute format('revoke execute on function %s from public, anon, authenticated', sig);
       execute format('grant execute on function %s to service_role', sig);`,
      ),
    );
    expect(out.dynamic).toBe(false);
    expect(out.statements.map((s) => s.text.trim())).toEqual([
      "revoke execute on function public.alpha from public, anon, authenticated",
      "revoke execute on function public.beta from public, anon, authenticated",
      "grant execute on function public.alpha to service_role",
      "grant execute on function public.beta to service_role",
    ]);
  });

  it("refuses a lookup that is not pinned to the outer name, the schema and SECURITY DEFINER", () => {
    // Each of these selects can yield a function the outer list never named, so nothing is unrolled.
    for (const where of [
      "n.nspname = 'public' and p.prosecdef", // every definer function of the schema
      "n.nspname = 'public' and p.proname = fn", // invoker functions too
      "p.proname = fn and p.prosecdef", // any schema
      "n.nspname = 'public' and p.proname like fn and p.prosecdef", // not an equality
    ]) {
      const out = expand(
        sweep(where, `execute format('revoke execute on function %s from anon', sig);`),
      );
      expect(out.statements, where).toEqual([]);
      expect(out.dynamic, where).toBe(true);
    }
  });

  it("still unrolls the plain literal loop and still gives up on what it cannot follow", () => {
    const plain = expand(`do $$
declare t text; names text[] := array['job_queue', 'send_ledger'];
begin
  foreach t in array names loop
    execute format('alter table public.%I enable row level security', t);
  end loop;
end $$;`);
    expect(plain.dynamic).toBe(false);
    expect(plain.statements.map((s) => s.text.trim())).toEqual([
      "alter table public.job_queue enable row level security",
      "alter table public.send_ledger enable row level security",
    ]);
    const overQuery = expand(`do $$
declare r record;
begin
  for r in select policyname, tablename from pg_policies where schemaname = 'public' loop
    execute format('drop policy %I on public.%I', r.policyname, r.tablename);
  end loop;
end $$;`);
    expect(overQuery.statements).toEqual([]);
    expect(overQuery.dynamic).toBe(true);
  });
});
