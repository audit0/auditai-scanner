import { fileURLToPath } from "node:url";
import { buildGraph } from "@auditai/graph";
import { parseProject } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { runRules } from "../rule.js";
import {
  isObjectIdColumn,
  isScopeColumn,
  policyScopesToCaller,
  supabaseAuthorizationPack,
} from "./supabase-authorization.js";

const fixture = (variant: "vulnerable" | "secure"): string =>
  fileURLToPath(
    new URL(
      `../../../../evals/fixtures/001-cross-tenant-invoice-read/${variant}/`,
      import.meta.url,
    ),
  );

function scan(dir: string) {
  const model = parseProject(dir, { sqlDirs: ["../supabase"] });
  return {
    model,
    findings: runRules(supabaseAuthorizationPack, model, buildGraph(model), {
      now: "2026-09-11T00:00:00Z",
    }),
  };
}

describe("column classifiers", () => {
  it("separates object ids from scope columns", () => {
    expect(isObjectIdColumn("id")).toBe(true);
    expect(isObjectIdColumn("invoice_id")).toBe(true);
    expect(isObjectIdColumn("tenant_id")).toBe(false);
    expect(isScopeColumn("owner_id")).toBe(true);
    expect(isScopeColumn("status")).toBe(false);
    expect(isObjectIdColumn(null)).toBe(false);
  });

  it("recognises caller-scoped policy expressions", () => {
    expect(policyScopesToCaller("true")).toBe(false);
    expect(policyScopesToCaller("auth.role() = 'authenticated'")).toBe(false);
    expect(policyScopesToCaller("tenant_id = public.current_tenant_id()")).toBe(true);
    expect(policyScopesToCaller("id = auth.uid()")).toBe(true);
    expect(policyScopesToCaller(null)).toBe(false);
  });
});

describe("supabase authorization pack on fixture 001", () => {
  it("flags the vulnerable handler as a likely cross-tenant read", () => {
    const { findings, model } = scan(fixture("vulnerable"));
    expect(model.warnings).toEqual([]);
    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f).toMatchObject({
      id: "AUDIT-001",
      ruleId: "supabase.service-role-object-access-without-tenant-scope",
      status: "likely",
      severity: "critical",
      entrypoints: ["GET /api/invoices/[id]"],
      sources: ["route_param:id"],
      sinks: ["supabase.select:public.invoices"],
    });
    expect(f?.title).toBe('Cross-tenant select on "invoices" via service-role client');
    expect(f?.evidence[0]?.locations?.map((l) => l.file)).toEqual([
      "app/api/invoices/[id]/route.ts",
      "app/api/invoices/[id]/route.ts",
      "lib/supabase.ts",
    ]);
    expect(f?.evidence[0]?.summary).toContain("RLS is enabled on public.invoices");
  });

  it("stays silent on the secure handler", () => {
    const { findings } = scan(fixture("secure"));
    expect(findings).toEqual([]);
  });
});
