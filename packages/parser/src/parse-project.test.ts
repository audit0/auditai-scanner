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

  it("reads quoted, schema-qualified and multi-line statements (Makerkit, Drizzle output)", () => {
    const into = new Map<string, RlsTable>();
    parseSqlForRls(
      "m.sql",
      `create table if not exists\n  public.accounts (\n    id uuid primary key,\n    name text\n  );\n\n-- Enable RLS on the accounts table\nalter table "public"."accounts"\n    enable row level security;\n\ncreate table "public"."todo_list" (id int, owner_id uuid);\nalter table "public"."todo_list" enable row level security;\ncreate policy "Users can read own" on "public"."todo_list" for select using (auth.uid() = owner_id);`,
      into,
    );
    expect(into.get("accounts")).toMatchObject({ rlsEnabled: true, columns: ["id", "name"] });
    expect(into.get("todo_list")).toMatchObject({
      rlsEnabled: true,
      policies: ["Users can read own"],
    });
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
    // The call to getUserFromRequest and the auth.getUser inside it: an auth helper is followed
    // like any other helper since 12 September 2026, so its own evidence is recorded too.
    expect(r?.authChecks.length).toBeGreaterThanOrEqual(1);
    expect(r?.authChecks.every((a) => a.kind === "session")).toBe(true);
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
    // `profile` is the caller's own row (selected by the session user's id), so its tenant is identity.
    expect(invoices?.filters).toContainEqual({
      method: "eq",
      column: "tenant_id",
      valueText: "profile.tenant_id",
      inputDerived: false,
      identity: true,
    });
  });

  it("survives a directory with no code", () => {
    const m = parseProject(fileURLToPath(new URL("../../../evals/harness/", import.meta.url)));
    expect(m.routes).toEqual([]);
  });
});

import { matchPattern, resolveExports } from "./resolve.js";

async function tempProject(files: Record<string, string>): Promise<string> {
  const { mkdtempSync, mkdirSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { dirname, join } = await import("node:path");
  const dir = mkdtempSync(join(tmpdir(), "auditai-proj-"));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}

describe("import resolution", () => {
  it("maps package.json exports, including conditions and wildcards", () => {
    expect(resolveExports("./src/index.ts", ".")).toEqual(["./src/index.ts"]);
    expect(resolveExports({ "./server": "./src/server.ts" }, "./server")).toEqual([
      "./src/server.ts",
    ]);
    expect(resolveExports({ "./hooks/*": "./src/hooks/*.ts" }, "./hooks/use-x")).toEqual([
      "./src/hooks/use-x.ts",
    ]);
    expect(
      resolveExports({ ".": { import: "./dist/index.js", types: "./dist/index.d.ts" } }, "."),
    ).toEqual(["./dist/index.js"]);
    expect(resolveExports({ import: "./a.js", default: "./b.js" }, ".")).toEqual(["./a.js"]);
    expect(resolveExports(null, ".")).toEqual([]);
    expect(matchPattern("~/*", "~/lib/http")).toBe("lib/http");
    expect(matchPattern("@kit/*", "@other/x")).toBeNull();
  });

  it("follows a class-based service and a tsconfig path alias into the query", async () => {
    const dir = await tempProject({
      "tsconfig.json": JSON.stringify({ compilerOptions: { paths: { "~/*": ["./src/*"] } } }),
      "src/lib/supabase.ts": `import { createClient } from "@supabase/supabase-js";
export function getAdmin() { return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!); }
export function getDb() { return getAdmin(); }
`,
      "src/lib/accounts.ts": `import type { SupabaseClient } from "@supabase/supabase-js";
class AccountsApi {
  constructor(private readonly client: SupabaseClient) {}
  async getAccount(id: string) {
    return this.client.from("accounts").select("*").eq("id", id).single();
  }
  async getMine(id: string) { return this.getAccount(id); }
}
export function createAccountsApi(client: SupabaseClient) { return new AccountsApi(client); }
`,
      "src/app/api/accounts/[id]/route.ts": `import { NextResponse } from "next/server";
import { getDb } from "~/lib/supabase";
import { createAccountsApi } from "~/lib/accounts";
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const api = createAccountsApi(getDb());
  const { data } = await api.getMine(id);
  return NextResponse.json(data);
}
`,
    });
    const m = parseProject(dir);
    expect(m.warnings).toEqual([]);
    expect(m.routes).toHaveLength(1);
    const q = m.routes[0]?.queries[0];
    expect(q).toMatchObject({ table: "accounts", operation: "select", client: "service_role" });
    expect(q?.filters).toEqual([
      { method: "eq", column: "id", valueText: "id", inputDerived: true },
    ]);
    expect(q?.location.file).toBe("src/lib/accounts.ts");
    expect(q?.via?.map((v) => v.split(" ")[0])).toEqual([
      "AccountsApi.getMine",
      "AccountsApi.getAccount",
    ]);
  });

  it("treats a dynamic page as an entry point with params as input", async () => {
    const dir = await tempProject({
      "lib/admin.ts": `import { createClient } from "@supabase/supabase-js";
export const admin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
`,
      "app/invoices/[id]/page.tsx": `import { admin } from "@/lib/admin";
export default async function InvoicePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { data } = await admin.from("invoices").select("*").eq("id", id).single();
  return <pre>{JSON.stringify(data)}</pre>;
}
`,
    });
    const m = parseProject(dir);
    const r = m.routes[0];
    expect(r?.entry).toBe("PAGE /invoices/[id]");
    expect(r?.kind).toBe("page");
    expect(r?.inputs).toContainEqual(expect.objectContaining({ kind: "route_param", name: "id" }));
    expect(r?.queries[0]).toMatchObject({ client: "service_role", clientName: "admin" });
    expect(r?.queries[0]?.filters[0]).toMatchObject({ column: "id", inputDerived: true });
  });

  it("sees through wrapped handlers and keeps auth-helper results untainted", async () => {
    const dir = await tempProject({
      "lib/supabase.ts": `import { createClient } from "@supabase/supabase-js";
export function admin() { return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!); }
export async function getUserFromRequest(req: Request) { const { data } = await admin().auth.getUser(req.headers.get("authorization") ?? ""); return data.user; }
`,
      "lib/wrap.ts": `export function withAuth<T>(fn: (req: Request) => Promise<T>) { return fn; }`,
      "app/api/me/route.ts": `import { NextResponse } from "next/server";
import { admin, getUserFromRequest } from "@/lib/supabase";
import { withAuth } from "@/lib/wrap";
export const GET = withAuth(async (req: Request) => {
  const user = await getUserFromRequest(req);
  const { data } = await admin().from("profiles").select("*").eq("id", user!.id).single();
  return NextResponse.json(data);
});
`,
    });
    const m = parseProject(dir);
    const r = m.routes[0];
    expect(r?.entry).toBe("GET /api/me");
    expect(r?.authChecks.length).toBeGreaterThanOrEqual(1);
    expect(r?.queries[0]?.filters[0]).toMatchObject({ column: "id", inputDerived: false });
  });
});

describe("direct database connections (Drizzle, Prisma)", () => {
  it("reads Drizzle select/insert/relational queries with predicates and a module-level client", async () => {
    const dir = await tempProject({
      "db/schema.ts": `import { pgTable, uuid, text } from "drizzle-orm/pg-core";
export const invoices = pgTable("invoices", { id: uuid("id").primaryKey(), tenantId: uuid("tenant_id"), status: text("status") });
export const profiles = pgTable("profiles", { id: uuid("id").primaryKey(), tenantId: uuid("tenant_id") });
`,
      "lib/db.ts": `import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "@/db/schema";
export const db = drizzle(postgres(process.env.DATABASE_URL!), { schema });
`,
      "app/api/invoices/[id]/route.ts": `import { and, eq, inArray } from "drizzle-orm";
import { NextResponse } from "next/server";
import * as schema from "@/db/schema";
import { invoices } from "@/db/schema";
import { db } from "@/lib/db";
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const [row] = await db.select().from(invoices).where(eq(invoices.id, id)).limit(1);
  const mine = await db.query.profiles.findFirst({ where: (t, { eq }) => eq(t.id, "fixed") });
  await db.update(schema.invoices).set({ status: "paid" }).where(and(eq(schema.invoices.id, id), eq(schema.invoices.tenantId, mine!.tenantId)));
  await db.transaction(async (tx) => { await tx.delete(invoices).where(inArray(invoices.id, [id])); });
  return NextResponse.json(row);
}
`,
    });
    const m = parseProject(dir);
    const qs = m.routes[0]?.queries ?? [];
    expect(qs.map((q) => [q.table, q.operation, q.client, q.clientName])).toEqual([
      ["invoices", "select", "direct_db", "db"],
      ["profiles", "select", "direct_db", "db"],
      ["invoices", "update", "direct_db", "db"],
      ["invoices", "delete", "direct_db", "db"],
    ]);
    expect(qs[0]?.filters).toEqual([
      { method: "eq", column: "id", valueText: "id", inputDerived: true },
    ]);
    expect(qs[1]?.filters).toEqual([
      { method: "eq", column: "id", valueText: '"fixed"', inputDerived: false },
    ]);
    expect(qs[2]?.filters.map((f) => [f.column, f.inputDerived])).toEqual([
      ["id", true],
      ["tenantId", false],
    ]);
    expect(qs[2]?.payload?.text).toBe('{ status: "paid" }');
    expect(qs[3]?.filters[0]).toMatchObject({
      method: "inArray",
      column: "id",
      inputDerived: true,
    });
    expect(qs[0]?.clientLocation?.file).toBe("lib/db.ts");
  });

  it("reads Prisma calls through the global singleton and maps models to tables via @@map", async () => {
    const dir = await tempProject({
      "prisma/schema.prisma": `model Invoice { id String @id\n tenantId String\n @@map("invoices") }\nmodel Profile { id String @id }`,
      "lib/prisma.ts": `import { PrismaClient } from "@prisma/client";
const g = globalThis as unknown as { prisma?: PrismaClient };
export const prisma = g.prisma ?? new PrismaClient();
`,
      "app/api/invoices/[id]/route.ts": `import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const body = await req.json();
  const p = await prisma.profile.findUnique({ where: { id: "me" } });
  await prisma.invoice.update({ where: { id, tenantId: p!.tenantId }, data: body });
  await prisma.invoice.delete({ where: { id } });
  return NextResponse.json({ ok: true });
}
`,
    });
    const m = parseProject(dir);
    const qs = m.routes[0]?.queries ?? [];
    expect(qs.map((q) => [q.table, q.operation, q.client])).toEqual([
      ["Profile", "select", "direct_db"],
      ["invoices", "update", "direct_db"],
      ["invoices", "delete", "direct_db"],
    ]);
    expect(qs[1]?.filters.map((f) => [f.column, f.inputDerived])).toEqual([
      ["id", true],
      ["tenantId", false],
    ]);
    expect(qs[1]?.payload).toMatchObject({ inputDerived: true, wholeInput: true });
    expect(qs[2]?.filters).toEqual([
      { method: "eq", column: "id", valueText: "id", inputDerived: true },
    ]);
    expect(qs[2]?.clientLocation?.file).toBe("lib/prisma.ts");
  });
});

describe("secret exposures", () => {
  it("flags real process.env reads of a public secret, not the same text in strings or comments", async () => {
    const dir = await tempProject({
      "lib/docs.ts": `// process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY is what the vulnerable example reads
export const example = 'createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!)';
export const template = \`key: process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY\`;
`,
      "lib/leak.ts": `export const a = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;
export const b = process.env["NEXT_PUBLIC_STRIPE_SECRET"];
export const ok = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
`,
    });
    const m = parseProject(dir);
    expect(m.exposures.map((e) => [e.location.file, e.location.line, e.kind])).toEqual([
      ["lib/leak.ts", 1, "public_env_service_role"],
      ["lib/leak.ts", 2, "public_env_service_role"],
    ]);
    expect(m.exposures[1]?.evidence).toContain("process.env.NEXT_PUBLIC_STRIPE_SECRET");
  });
});
