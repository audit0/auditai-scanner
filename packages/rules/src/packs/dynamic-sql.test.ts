import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildGraph } from "@auditai/graph";
import { parseProject } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { defaultRules } from "../index.js";
import { runRules } from "../rule.js";
import { dynamicSqlFromFunctionParameter } from "./supabase-storage-rpc.js";

const NOW = "2026-09-26T00:00:00Z";

function tempProject(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "auditai-dynamic-sql-"));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}

function findingsFor(sql: string) {
  const model = parseProject(tempProject({ "supabase/migrations/0001.sql": sql }));
  return runRules([dynamicSqlFromFunctionParameter], model, buildGraph(model), { now: NOW });
}

const glued = (name: string, security: string) => `
create function public.${name}(p_status text) returns setof public.orders
language plpgsql ${security} set search_path = '' as $$
begin
  return query execute 'select * from public.orders where status = ''' || p_status || '''';
end $$;`;

describe("supabase.dynamic-sql-from-function-parameter", () => {
  it("fixture 045: one finding on the vulnerable app, none on the secure one", () => {
    const dir = (variant: string) =>
      fileURLToPath(
        new URL(
          `../../../../evals/fixtures/045-dynamic-sql-from-function-parameter/${variant}/`,
          import.meta.url,
        ),
      );
    const scan = (variant: string) => {
      const model = parseProject(dir(variant));
      return runRules(defaultRules, model, buildGraph(model), { now: NOW });
    };
    const vulnerable = scan("vulnerable");
    expect(vulnerable.map((f) => [f.ruleId, f.severity])).toEqual([
      [dynamicSqlFromFunctionParameter.id, "critical"],
    ]);
    expect(vulnerable[0]?.evidence[0]?.data).toMatchObject({
      function: "search_invoices",
      parameters: ["p_customer"],
      securityDefiner: true,
    });
    expect(scan("secure")).toEqual([]);
  });

  it("rates by who can execute it and whether it runs as its owner", () => {
    const findings = findingsFor(`
create table public.orders (id uuid primary key, status text);
${glued("definer_anon", "security definer")}
${glued("definer_signed_in", "security definer")}
revoke execute on function public.definer_signed_in(text) from public, anon;
${glued("invoker_anon", "security invoker")}
`);
    expect(findings.map((f) => [f.title, f.severity])).toEqual([
      ['SQL injection through parameter "p_status" of "definer_anon"', "critical"],
      ['SQL injection through parameter "p_status" of "definer_signed_in"', "high"],
      ['SQL injection through parameter "p_status" of "invoker_anon"', "medium"],
    ]);
    expect(findings[0]?.entrypoints).toEqual(["POST /rest/v1/rpc/definer_anon"]);
    expect(findings[0]?.sinks).toEqual(["postgres.execute:public.definer_anon"]);
  });

  it("skips functions no API role can execute, other schemas and trigger functions", () => {
    const findings = findingsFor(`
create table public.orders (id uuid primary key, status text);
${glued("server_only", "security definer")}
revoke execute on function public.server_only(text) from public, anon, authenticated;
create function private.hidden(p_status text) returns void language plpgsql security definer as $$
begin execute 'delete from public.orders where status = ''' || p_status || ''''; end $$;
create function public.audit_row() returns trigger language plpgsql security definer as $$
begin execute 'insert into log values (''' || tg_table_name || ''')'; return new; end $$;
`);
    expect(findings).toEqual([]);
  });

  it("stays silent when every parameter is bound or quoted", () => {
    const findings = findingsFor(`
create table public.orders (id uuid primary key, status text);
create function public.bound(p_status text, p_sort text) returns setof public.orders
language plpgsql security definer set search_path = '' as $$
begin
  if p_sort not in ('created_at', 'status') then raise exception 'bad sort'; end if;
  return query execute format('select * from public.orders where status = %L order by %I', p_status, p_sort);
end $$;
`);
    expect(findings).toEqual([]);
  });
});
