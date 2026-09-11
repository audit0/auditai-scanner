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

describe("policy findings are reported once per policy", () => {
  it("merges two handlers that reach the same permissive policy into one finding", async () => {
    const { cpSync, mkdirSync, mkdtempSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const src = fileURLToPath(
      new URL("../../../../evals/fixtures/003-rls-policy-using-true/vulnerable/", import.meta.url),
    );
    const dir = mkdtempSync(join(tmpdir(), "auditai-dedupe-"));
    cpSync(src, dir, { recursive: true });
    mkdirSync(join(dir, "app/api/invoices/recent"), { recursive: true });
    writeFileSync(
      join(dir, "app/api/invoices/recent/route.ts"),
      `import { NextResponse } from "next/server";
import { bearerToken, createRequestClient } from "@/lib/supabase";
export async function GET(req: Request) {
  const token = bearerToken(req);
  if (!token) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const supabase = createRequestClient(token);
  const { data } = await supabase.from("invoices").select("*").limit(20);
  return NextResponse.json({ invoices: data ?? [] });
}
`,
    );
    const model = parseProject(dir, { sqlDirs: ["supabase/migrations"] });
    const findings = runRules(supabaseAuthorizationPack, model, buildGraph(model), {
      now: "2026-09-11T00:00:00Z",
    });
    const policy = findings.filter(
      (f) => f.ruleId === "supabase.rls-policy-without-caller-predicate",
    );
    expect(policy).toHaveLength(1);
    expect(policy[0]?.entrypoints.sort()).toEqual([
      "GET /api/invoices/[id]",
      "GET /api/invoices/recent",
    ]);
    expect(policy[0]?.evidence[0]?.summary).toContain("Reached from 2 entry points");
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
