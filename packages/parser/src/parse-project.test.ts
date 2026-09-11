import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { RlsTable } from "./model.js";
import { routeFromFile } from "./nextjs.js";
import { parseProject } from "./parse-project.js";
import { parseSqlForRls } from "./rls.js";

const fixture = (variant: "vulnerable" | "secure"): string =>
  fileURLToPath(
    new URL(`../../../evals/fixtures/001-cross-tenant-invoice-read/${variant}/`, import.meta.url),
  );
const SQL = { sqlDirs: ["../supabase"] };

describe("routeFromFile", () => {
  it("maps app router files to routes", () => {
    expect(routeFromFile("app/api/invoices/[id]/route.ts")).toBe("/api/invoices/[id]");
    expect(routeFromFile("src/app/(dashboard)/@modal/items/route.tsx")).toBe("/items");
    expect(routeFromFile("app/route.ts")).toBe("/");
    expect(routeFromFile("apps/web/app/api/invoices/route.ts")).toBe("/api/invoices");
    expect(routeFromFile("app/api/invoices/[id]/page.tsx")).toBeNull();
    expect(routeFromFile("lib/route.ts")).toBeNull();
  });
});

describe("parseSqlForRls", () => {
  it("tracks rls state and policies per table", () => {
    const into = new Map<string, RlsTable>();
    parseSqlForRls(
      "m.sql",
      `create table public.a (id int);\n-- alter table a enable row level security (comment)\nalter table public.a enable row level security;\ncreate policy "read own" on public.a for select using (true);\ncreate table b (id int);`,
      into,
    );
    expect(into.get("a")).toMatchObject({
      rlsEnabled: true,
      policies: ["read own"],
      columns: ["id"],
    });
    expect(into.get("a")?.policyDetails[0]).toMatchObject({
      command: "select",
      using: "true",
      check: null,
    });
    expect(into.get("b")).toMatchObject({ rlsEnabled: false, policies: [] });
  });
});

describe("client classification", () => {
  it("resolves key identifiers to their declarations", async () => {
    const { mkdtempSync, mkdirSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const dir = mkdtempSync(join(tmpdir(), "auditai-cls-"));
    mkdirSync(join(dir, "lib"), { recursive: true });
    writeFileSync(
      join(dir, "lib/admin.ts"),
      `import { createClient } from "@supabase/supabase-js";
export function getAdminClient() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return null;
  return createClient(url, key, { auth: { persistSession: false } });
}
export function getAnonClient() {
  const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;
  return createClient(process.env.SUPABASE_URL!, key);
}
`,
    );
    const m = parseProject(dir);
    expect(m.clientFactories.map((c) => [c.name, c.kind])).toEqual([
      ["getAdminClient", "service_role"],
      ["getAnonClient", "anon"],
    ]);
  });
});

describe("parseProject on fixture 001", () => {
  it("models the vulnerable handler: service-role client, id from params, no tenant scope", () => {
    const m = parseProject(fixture("vulnerable"), SQL);
    expect(m.tables.map((t) => [t.table, t.rlsEnabled, t.policies.length])).toEqual([
      ["tenants", true, 1],
      ["profiles", true, 1],
      ["invoices", true, 2],
    ]);
    expect(m.routes).toHaveLength(1);
    const r = m.routes[0];
    expect(r?.route).toBe("/api/invoices/[id]");
    expect(r?.entry).toBe("GET /api/invoices/[id]");
    expect(r?.kind).toBe("route");
    expect(r?.method).toBe("GET");
    expect(r?.inputs).toContainEqual(expect.objectContaining({ kind: "route_param", name: "id" }));
    expect(r?.authChecks).toHaveLength(1);
    expect(r?.queries).toHaveLength(1);
    const q = r?.queries[0];
    expect(q).toMatchObject({
      table: "invoices",
      operation: "select",
      client: "service_role",
      clientName: "createServiceRoleClient",
    });
    expect(q?.filters).toEqual([
      { method: "eq", column: "id", valueText: "id", inputDerived: true },
    ]);
    expect(m.clientFactories.map((c) => [c.name, c.kind])).toContainEqual([
      "createServiceRoleClient",
      "service_role",
    ]);
    expect(m.authHelpers.map((a) => a.name)).toContain("getUserFromRequest");
    expect(m.warnings).toEqual([]);
  });

  it("models the secure handler: user-scoped client and tenant scoping", () => {
    const m = parseProject(fixture("secure"), SQL);
    const r = m.routes[0];
    expect(r?.authChecks.length).toBeGreaterThanOrEqual(1);
    const invoices = r?.queries.find((q) => q.table === "invoices");
    expect(invoices).toMatchObject({
      operation: "select",
      client: "user_scoped",
      clientName: "createRequestClient",
    });
    expect(invoices?.filters).toContainEqual({
      method: "eq",
      column: "id",
      valueText: "id",
      inputDerived: true,
    });
    expect(invoices?.filters).toContainEqual({
      method: "eq",
      column: "tenant_id",
      valueText: "profile.tenant_id",
      inputDerived: false,
    });
  });

  it("survives a directory with no code", () => {
    const m = parseProject(fileURLToPath(new URL("../../../evals/harness/", import.meta.url)));
    expect(m.routes).toEqual([]);
  });
});
