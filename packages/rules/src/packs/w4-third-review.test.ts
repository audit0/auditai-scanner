import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Finding } from "@auditai/core";
import { buildGraph } from "@auditai/graph";
import { parseProject } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { runRules } from "../rule.js";
import { supabaseAuthorizationPack } from "./supabase-authorization.js";
import { supabaseStorageRpcPack } from "./supabase-storage-rpc.js";

/**
 * The third review of the round-8 W4 branch (scratchpad verify-W4-r3): projects in which an
 * anonymous request reaches a service-role query, each of which the middleware gate once silenced.
 * The gate is cut, so R7 must report every one; the passkey counterexample (w1) sits next to its
 * twin, which the passkey check still accepts.
 */

const R7 = "supabase.service-role-query-without-authentication";

function scan(files: Record<string, string>): Finding[] {
  const dir = mkdtempSync(join(tmpdir(), "auditai-w4-r3-"));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  const model = parseProject(dir, { sqlDirs: ["supabase/migrations"] });
  return runRules(
    [...supabaseAuthorizationPack, ...supabaseStorageRpcPack],
    model,
    buildGraph(model),
    {
      now: "2026-09-23T00:00:00Z",
    },
  );
}

const r7Entries = (name: string): string[] =>
  scan(project(name))
    .filter((f) => f.ruleId === R7)
    .map((f) => f.entrypoints[0] ?? "");

function project(name: string): Record<string, string> {
  const p = PROJECTS[name];
  if (!p) throw new Error(`no project ${name}`);
  return p;
}

describe("R7 on the third review's counterexamples (middleware gate cut)", () => {
  it("a-local-arrow-param-write: a local arrow writes the getUser() result it is handed", () => {
    expect(r7Entries("a-local-arrow-param-write")).toEqual(["GET /api/invoices"]);
  });

  it("b-toplevel-helper-inner-alias: a top-level helper writes through an alias of its parameter", () => {
    expect(r7Entries("b-toplevel-helper-inner-alias")).toEqual(["GET /api/invoices"]);
  });

  it("c-two-level-helper: the write sits one helper deeper", () => {
    expect(r7Entries("c-two-level-helper")).toEqual(["GET /api/invoices"]);
  });

  it("d-lodash-merge: lodash merge() writes a user into the result", () => {
    expect(r7Entries("d-lodash-merge")).toEqual(["GET /api/invoices"]);
  });

  it("e-hoisted-nested-fn: a hoisted nested function declared after the return writes the result", () => {
    expect(r7Entries("e-hoisted-nested-fn")).toEqual(["GET /api/invoices"]);
  });

  it("j-local-object-method: a method of a module object writes the result", () => {
    expect(r7Entries("j-local-object-method")).toEqual(["GET /api/invoices"]);
  });

  it("l-object-alias-assign: Object.assign through an alias of Object", () => {
    expect(r7Entries("l-object-alias-assign")).toEqual(["GET /api/invoices"]);
  });

  it("y4a-holder-object-alias: the result is held in an object and written through it", () => {
    expect(r7Entries("y4a-holder-object-alias")).toEqual(["GET /api/invoices"]);
  });

  it("y4b-array-destructure-alias: the result is destructured out of an array and written", () => {
    expect(r7Entries("y4b-array-destructure-alias")).toEqual(["GET /api/invoices"]);
  });

  it("a-twin-toplevel-param-write: twin: a top-level helper writes its parameter directly", () => {
    expect(r7Entries("a-twin-toplevel-param-write")).toEqual(["GET /api/invoices"]);
  });

  it("m-try-catch-stale-write: the catch falls through with a user written inside the try", () => {
    expect(r7Entries("m-try-catch-stale-write")).toEqual(["GET /api/invoices"]);
  });

  it("f-matcher-extension-quantifier: a matcher lookahead with a quantified extension skips /api/export/invoices.csv", () => {
    expect(r7Entries("f-matcher-extension-quantifier")).toEqual(["GET /api/export/[file]"]);
  });

  it("f-twin-extension-list: twin: a matcher with an explicit extension list", () => {
    expect(r7Entries("f-twin-extension-list")).toEqual(["GET /api/export/[file]"]);
  });

  it("g-percent5F-underscore-folder: a %5F folder is served under /_internal, which the middleware lets through", () => {
    expect(r7Entries("g-percent5F-underscore-folder")).toEqual(["GET /%5Finternal/stats"]);
  });

  it("h-open-range-pnpm-lock: an open next range pinned by pnpm-lock.yaml to a version with a bypass", () => {
    expect(r7Entries("h-open-range-pnpm-lock")).toEqual(["GET /api/reports/[period]"]);
  });

  it("h-twin-caret-range: twin: a caret range on the same version", () => {
    expect(r7Entries("h-twin-caret-range")).toEqual(["GET /api/reports/[period]"]);
  });
});

describe("a passkey helper whose result the handler ignores", () => {
  it("w1: an early return before the verification lets a request without an assertion through", () => {
    expect(r7Entries("w1-passkey-helper-early-return")).toEqual(["POST /api/passkey/login"]);
  });

  it("w1 twin: the helper verifies unconditionally and throws on a failed assertion", () => {
    expect(r7Entries("w1-twin-no-early-return")).toEqual([]);
  });
});

const PROJECTS: Record<string, Record<string, string>> = {
  "a-local-arrow-param-write": {
    "app/api/invoices/route.ts":
      'import { admin } from "@/lib/admin";\nexport async function GET() {\n  const { data } = await admin.from("invoices").select("*");\n  return Response.json(data);\n}\n',
    "lib/admin.ts":
      'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n',
    "middleware.ts":
      'import { createServerClient } from "@supabase/ssr";\nimport { NextResponse, type NextRequest } from "next/server";\nexport async function middleware(request: NextRequest) {\n  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {\n    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },\n  });\n  const { data } = await supabase.auth.getUser();\n  const withDemoUser = (d: any) => {\n    if (request.nextUrl.searchParams.get("demo") === "1") d.user = { id: "demo" };\n  };\n  withDemoUser(data);\n  if (!data.user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });\n  return NextResponse.next();\n}\nexport const config = { matcher: ["/api/:path*"] };\n',
    "package.json":
      '{"name": "a-local-arrow-param-write", "private": true, "dependencies": {"next": "15.5.25", "@supabase/supabase-js": "2.49.0", "@supabase/ssr": "0.6.1", "next-auth": "4.24.11", "@simplewebauthn/server": "13.1.1", "react": "19.1.0"}}\n',
    "supabase/migrations/0001_init.sql":
      "create table public.invoices (id uuid primary key, org_id uuid, total numeric);\nalter table public.invoices enable row level security;\ncreate table public.users (id uuid primary key, email text, public_key text, counter int);\nalter table public.users enable row level security;\n",
    "tsconfig.json":
      '{ "compilerOptions": { "strict": true, "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
  },
  "b-toplevel-helper-inner-alias": {
    "app/api/invoices/route.ts":
      'import { admin } from "@/lib/admin";\nexport async function GET() {\n  const { data } = await admin.from("invoices").select("*");\n  return Response.json(data);\n}\n',
    "lib/admin.ts":
      'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n',
    "middleware.ts":
      'import { createServerClient } from "@supabase/ssr";\nimport { NextResponse, type NextRequest } from "next/server";\nfunction withDemoUser(d: any, request: NextRequest) {\n  const target = d;\n  if (request.nextUrl.searchParams.get("demo") === "1") target.user = { id: "demo" };\n}\nexport async function middleware(request: NextRequest) {\n  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {\n    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },\n  });\n  const { data } = await supabase.auth.getUser();\n  withDemoUser(data, request);\n  if (!data.user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });\n  return NextResponse.next();\n}\nexport const config = { matcher: ["/api/:path*"] };\n',
    "package.json":
      '{"name": "b-toplevel-helper-inner-alias", "private": true, "dependencies": {"next": "15.5.25", "@supabase/supabase-js": "2.49.0", "@supabase/ssr": "0.6.1", "next-auth": "4.24.11", "@simplewebauthn/server": "13.1.1", "react": "19.1.0"}}\n',
    "supabase/migrations/0001_init.sql":
      "create table public.invoices (id uuid primary key, org_id uuid, total numeric);\nalter table public.invoices enable row level security;\ncreate table public.users (id uuid primary key, email text, public_key text, counter int);\nalter table public.users enable row level security;\n",
    "tsconfig.json":
      '{ "compilerOptions": { "strict": true, "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
  },
  "c-two-level-helper": {
    "app/api/invoices/route.ts":
      'import { admin } from "@/lib/admin";\nexport async function GET() {\n  const { data } = await admin.from("invoices").select("*");\n  return Response.json(data);\n}\n',
    "lib/admin.ts":
      'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n',
    "lib/demo.ts":
      'import type { NextRequest } from "next/server";\nfunction applyDemo(d: any) {\n  d.user = { id: "demo" };\n}\nexport function withDemoUser(d: any, request: NextRequest) {\n  if (request.nextUrl.searchParams.get("demo") === "1") applyDemo(d);\n}\n',
    "middleware.ts":
      'import { createServerClient } from "@supabase/ssr";\nimport { NextResponse, type NextRequest } from "next/server";\nimport { withDemoUser } from "@/lib/demo";\nexport async function middleware(request: NextRequest) {\n  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {\n    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },\n  });\n  const { data } = await supabase.auth.getUser();\n  withDemoUser(data, request);\n  if (!data.user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });\n  return NextResponse.next();\n}\nexport const config = { matcher: ["/api/:path*"] };\n',
    "package.json":
      '{"name": "c-two-level-helper", "private": true, "dependencies": {"next": "15.5.25", "@supabase/supabase-js": "2.49.0", "@supabase/ssr": "0.6.1", "next-auth": "4.24.11", "@simplewebauthn/server": "13.1.1", "react": "19.1.0"}}\n',
    "supabase/migrations/0001_init.sql":
      "create table public.invoices (id uuid primary key, org_id uuid, total numeric);\nalter table public.invoices enable row level security;\ncreate table public.users (id uuid primary key, email text, public_key text, counter int);\nalter table public.users enable row level security;\n",
    "tsconfig.json":
      '{ "compilerOptions": { "strict": true, "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
  },
  "d-lodash-merge": {
    "app/api/invoices/route.ts":
      'import { admin } from "@/lib/admin";\nexport async function GET() {\n  const { data } = await admin.from("invoices").select("*");\n  return Response.json(data);\n}\n',
    "lib/admin.ts":
      'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n',
    "middleware.ts":
      'import { createServerClient } from "@supabase/ssr";\nimport { NextResponse, type NextRequest } from "next/server";\nimport merge from "lodash/merge";\nexport async function middleware(request: NextRequest) {\n  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {\n    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },\n  });\n  const { data } = await supabase.auth.getUser();\n  if (request.nextUrl.searchParams.get("demo") === "1") merge(data, { user: { id: "demo" } });\n  if (!data.user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });\n  return NextResponse.next();\n}\nexport const config = { matcher: ["/api/:path*"] };\n',
    "package.json":
      '{"name": "d-lodash-merge", "private": true, "dependencies": {"next": "15.5.25", "@supabase/supabase-js": "2.49.0", "@supabase/ssr": "0.6.1", "next-auth": "4.24.11", "@simplewebauthn/server": "13.1.1", "react": "19.1.0", "lodash": "4.17.21"}}\n',
    "supabase/migrations/0001_init.sql":
      "create table public.invoices (id uuid primary key, org_id uuid, total numeric);\nalter table public.invoices enable row level security;\ncreate table public.users (id uuid primary key, email text, public_key text, counter int);\nalter table public.users enable row level security;\n",
    "tsconfig.json":
      '{ "compilerOptions": { "strict": true, "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
  },
  "e-hoisted-nested-fn": {
    "app/api/invoices/route.ts":
      'import { admin } from "@/lib/admin";\nexport async function GET() {\n  const { data } = await admin.from("invoices").select("*");\n  return Response.json(data);\n}\n',
    "lib/admin.ts":
      'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n',
    "middleware.ts":
      'import { createServerClient } from "@supabase/ssr";\nimport { NextResponse, type NextRequest } from "next/server";\nexport async function middleware(request: NextRequest) {\n  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {\n    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },\n  });\n  const { data } = await supabase.auth.getUser();\n  if (request.nextUrl.searchParams.get("demo") === "1") useDemo();\n  if (!data.user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });\n  return NextResponse.next();\n  function useDemo() {\n    (data as any).user = { id: "demo" };\n  }\n}\nexport const config = { matcher: ["/api/:path*"] };\n',
    "package.json":
      '{"name": "e-hoisted-nested-fn", "private": true, "dependencies": {"next": "15.5.25", "@supabase/supabase-js": "2.49.0", "@supabase/ssr": "0.6.1", "next-auth": "4.24.11", "@simplewebauthn/server": "13.1.1", "react": "19.1.0"}}\n',
    "supabase/migrations/0001_init.sql":
      "create table public.invoices (id uuid primary key, org_id uuid, total numeric);\nalter table public.invoices enable row level security;\ncreate table public.users (id uuid primary key, email text, public_key text, counter int);\nalter table public.users enable row level security;\n",
    "tsconfig.json":
      '{ "compilerOptions": { "strict": true, "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
  },
  "j-local-object-method": {
    "app/api/invoices/route.ts":
      'import { admin } from "@/lib/admin";\nexport async function GET() {\n  const { data } = await admin.from("invoices").select("*");\n  return Response.json(data);\n}\n',
    "lib/admin.ts":
      'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n',
    "middleware.ts":
      'import { createServerClient } from "@supabase/ssr";\nimport { NextResponse, type NextRequest } from "next/server";\nconst demo = {\n  fill(d: any) { d.user = { id: "demo" }; },\n};\nexport async function middleware(request: NextRequest) {\n  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {\n    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },\n  });\n  const { data } = await supabase.auth.getUser();\n  if (request.nextUrl.searchParams.get("demo") === "1") demo.fill(data);\n  if (!data.user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });\n  return NextResponse.next();\n}\nexport const config = { matcher: ["/api/:path*"] };\n',
    "package.json":
      '{"name": "j-local-object-method", "private": true, "dependencies": {"next": "15.5.25", "@supabase/supabase-js": "2.49.0", "@supabase/ssr": "0.6.1", "next-auth": "4.24.11", "@simplewebauthn/server": "13.1.1", "react": "19.1.0"}}\n',
    "supabase/migrations/0001_init.sql":
      "create table public.invoices (id uuid primary key, org_id uuid, total numeric);\nalter table public.invoices enable row level security;\ncreate table public.users (id uuid primary key, email text, public_key text, counter int);\nalter table public.users enable row level security;\n",
    "tsconfig.json":
      '{ "compilerOptions": { "strict": true, "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
  },
  "l-object-alias-assign": {
    "app/api/invoices/route.ts":
      'import { admin } from "@/lib/admin";\nexport async function GET() {\n  const { data } = await admin.from("invoices").select("*");\n  return Response.json(data);\n}\n',
    "lib/admin.ts":
      'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n',
    "middleware.ts":
      'import { createServerClient } from "@supabase/ssr";\nimport { NextResponse, type NextRequest } from "next/server";\nconst O = Object;\nexport async function middleware(request: NextRequest) {\n  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {\n    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },\n  });\n  const { data } = await supabase.auth.getUser();\n  if (request.nextUrl.searchParams.get("demo") === "1") O.assign(data, { user: { id: "demo" } });\n  if (!data.user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });\n  return NextResponse.next();\n}\nexport const config = { matcher: ["/api/:path*"] };\n',
    "package.json":
      '{"name": "l-object-alias-assign", "private": true, "dependencies": {"next": "15.5.25", "@supabase/supabase-js": "2.49.0", "@supabase/ssr": "0.6.1", "next-auth": "4.24.11", "@simplewebauthn/server": "13.1.1", "react": "19.1.0"}}\n',
    "supabase/migrations/0001_init.sql":
      "create table public.invoices (id uuid primary key, org_id uuid, total numeric);\nalter table public.invoices enable row level security;\ncreate table public.users (id uuid primary key, email text, public_key text, counter int);\nalter table public.users enable row level security;\n",
    "tsconfig.json":
      '{ "compilerOptions": { "strict": true, "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
  },
  "y4a-holder-object-alias": {
    "app/api/invoices/route.ts":
      'import { admin } from "@/lib/admin";\nexport async function GET() {\n  const { data } = await admin.from("invoices").select("*");\n  return Response.json(data);\n}\n',
    "lib/admin.ts":
      'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n',
    "middleware.ts":
      'import { createServerClient } from "@supabase/ssr";\nimport { NextResponse, type NextRequest } from "next/server";\nexport async function middleware(request: NextRequest) {\n  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {\n    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },\n  });\n  const { data } = await supabase.auth.getUser();\n  const ctx = { auth: data, request };\n  if (request.nextUrl.searchParams.get("demo") === "1") (ctx.auth as any).user = { id: "demo" };\n  if (!data.user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });\n  return NextResponse.next();\n}\nexport const config = { matcher: ["/api/:path*"] };\n',
    "package.json":
      '{"name": "y4a-holder-object-alias", "private": true, "dependencies": {"next": "15.5.25", "@supabase/supabase-js": "2.49.0", "@supabase/ssr": "0.6.1", "next-auth": "4.24.11", "@simplewebauthn/server": "13.1.1", "react": "19.1.0"}}\n',
    "supabase/migrations/0001_init.sql":
      "create table public.invoices (id uuid primary key, org_id uuid, total numeric);\nalter table public.invoices enable row level security;\ncreate table public.users (id uuid primary key, email text, public_key text, counter int);\nalter table public.users enable row level security;\n",
    "tsconfig.json":
      '{ "compilerOptions": { "strict": true, "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
  },
  "y4b-array-destructure-alias": {
    "app/api/invoices/route.ts":
      'import { admin } from "@/lib/admin";\nexport async function GET() {\n  const { data } = await admin.from("invoices").select("*");\n  return Response.json(data);\n}\n',
    "lib/admin.ts":
      'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n',
    "middleware.ts":
      'import { createServerClient } from "@supabase/ssr";\nimport { NextResponse, type NextRequest } from "next/server";\nexport async function middleware(request: NextRequest) {\n  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {\n    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },\n  });\n  const { data } = await supabase.auth.getUser();\n  const [session] = [data];\n  if (request.nextUrl.searchParams.get("demo") === "1") (session as any).user = { id: "demo" };\n  if (!data.user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });\n  return NextResponse.next();\n}\nexport const config = { matcher: ["/api/:path*"] };\n',
    "package.json":
      '{"name": "y4b-array-destructure-alias", "private": true, "dependencies": {"next": "15.5.25", "@supabase/supabase-js": "2.49.0", "@supabase/ssr": "0.6.1", "next-auth": "4.24.11", "@simplewebauthn/server": "13.1.1", "react": "19.1.0"}}\n',
    "supabase/migrations/0001_init.sql":
      "create table public.invoices (id uuid primary key, org_id uuid, total numeric);\nalter table public.invoices enable row level security;\ncreate table public.users (id uuid primary key, email text, public_key text, counter int);\nalter table public.users enable row level security;\n",
    "tsconfig.json":
      '{ "compilerOptions": { "strict": true, "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
  },
  "a-twin-toplevel-param-write": {
    "app/api/invoices/route.ts":
      'import { admin } from "@/lib/admin";\nexport async function GET() {\n  const { data } = await admin.from("invoices").select("*");\n  return Response.json(data);\n}\n',
    "lib/admin.ts":
      'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n',
    "middleware.ts":
      'import { createServerClient } from "@supabase/ssr";\nimport { NextResponse, type NextRequest } from "next/server";\nfunction withDemoUser(d: any, request: NextRequest) {\n  if (request.nextUrl.searchParams.get("demo") === "1") d.user = { id: "demo" };\n}\nexport async function middleware(request: NextRequest) {\n  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {\n    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },\n  });\n  const { data } = await supabase.auth.getUser();\n  withDemoUser(data, request);\n  if (!data.user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });\n  return NextResponse.next();\n}\nexport const config = { matcher: ["/api/:path*"] };\n',
    "package.json":
      '{"name": "a-twin-toplevel-param-write", "private": true, "dependencies": {"next": "15.5.25", "@supabase/supabase-js": "2.49.0", "@supabase/ssr": "0.6.1", "next-auth": "4.24.11", "@simplewebauthn/server": "13.1.1", "react": "19.1.0"}}\n',
    "supabase/migrations/0001_init.sql":
      "create table public.invoices (id uuid primary key, org_id uuid, total numeric);\nalter table public.invoices enable row level security;\ncreate table public.users (id uuid primary key, email text, public_key text, counter int);\nalter table public.users enable row level security;\n",
    "tsconfig.json":
      '{ "compilerOptions": { "strict": true, "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
  },
  "m-try-catch-stale-write": {
    "app/api/invoices/route.ts":
      'import { admin } from "@/lib/admin";\nexport async function GET() {\n  const { data } = await admin.from("invoices").select("*");\n  return Response.json(data);\n}\n',
    "lib/admin.ts":
      'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n',
    "lib/audit.ts":
      // biome-ignore lint/suspicious/noTemplateCurlyInString: source text of the counterexample project
      'export async function recordDemoVisit(id: string) {\n  const r = await fetch(`https://audit.example.com/demo/${id}`, { method: "POST" });\n  if (!r.ok) throw new Error("audit failed");\n}\n',
    "middleware.ts":
      // biome-ignore lint/suspicious/noTemplateCurlyInString: source text of the counterexample project
      'import { createServerClient } from "@supabase/ssr";\nimport { NextResponse, type NextRequest } from "next/server";\nimport { recordDemoVisit } from "@/lib/audit";\nexport async function middleware(request: NextRequest) {\n  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {\n    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },\n  });\n  const { data } = await supabase.auth.getUser();\n  try {\n    const demo = request.nextUrl.searchParams.get("demo");\n    if (demo) {\n      (data as any).user = { id: `demo-${demo}` };\n      await recordDemoVisit(demo);\n      return NextResponse.redirect(new URL("/demo/welcome", request.url));\n    }\n  } catch (e) {\n    console.error("demo audit failed", e);\n  }\n  if (!data.user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });\n  return NextResponse.next();\n}\nexport const config = { matcher: ["/api/:path*"] };\n',
    "package.json":
      '{"name": "m-try-catch-stale-write", "private": true, "dependencies": {"next": "15.5.25", "@supabase/supabase-js": "2.49.0", "@supabase/ssr": "0.6.1", "next-auth": "4.24.11", "@simplewebauthn/server": "13.1.1", "react": "19.1.0"}}\n',
    "supabase/migrations/0001_init.sql":
      "create table public.invoices (id uuid primary key, org_id uuid, total numeric);\nalter table public.invoices enable row level security;\ncreate table public.users (id uuid primary key, email text, public_key text, counter int);\nalter table public.users enable row level security;\n",
    "tsconfig.json":
      '{ "compilerOptions": { "strict": true, "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
  },
  "f-matcher-extension-quantifier": {
    "app/api/export/[file]/route.ts":
      'import { admin } from "@/lib/admin";\nexport async function GET(_req: Request, { params }: { params: Promise<{ file: string }> }) {\n  const { file } = await params;\n  const { data } = await admin.from("invoices").select("*");\n  return new Response(JSON.stringify({ file, data }), { headers: { "content-type": "text/csv" } });\n}\n',
    "lib/admin.ts":
      'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n',
    "middleware.ts":
      'import { createServerClient } from "@supabase/ssr";\nimport { NextResponse, type NextRequest } from "next/server";\nexport async function middleware(request: NextRequest) {\n  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {\n    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },\n  });\n  const { data } = await supabase.auth.getUser();\n  if (!data.user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });\n  return NextResponse.next();\n}\nexport const config = { matcher: ["/((?!_next/static|_next/image|.*\\\\.[a-z]{2,4}$).*)"] };\n',
    "package.json":
      '{"name": "f-matcher-extension-quantifier", "private": true, "dependencies": {"next": "15.5.25", "@supabase/supabase-js": "2.49.0", "@supabase/ssr": "0.6.1", "next-auth": "4.24.11", "@simplewebauthn/server": "13.1.1", "react": "19.1.0"}}\n',
    "supabase/migrations/0001_init.sql":
      "create table public.invoices (id uuid primary key, org_id uuid, total numeric);\nalter table public.invoices enable row level security;\ncreate table public.users (id uuid primary key, email text, public_key text, counter int);\nalter table public.users enable row level security;\n",
    "tsconfig.json":
      '{ "compilerOptions": { "strict": true, "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
  },
  "f-twin-extension-list": {
    "app/api/export/[file]/route.ts":
      'import { admin } from "@/lib/admin";\nexport async function GET(_req: Request, { params }: { params: Promise<{ file: string }> }) {\n  const { file } = await params;\n  const { data } = await admin.from("invoices").select("*");\n  return new Response(JSON.stringify({ file, data }), { headers: { "content-type": "text/csv" } });\n}\n',
    "lib/admin.ts":
      'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n',
    "middleware.ts":
      'import { createServerClient } from "@supabase/ssr";\nimport { NextResponse, type NextRequest } from "next/server";\nexport async function middleware(request: NextRequest) {\n  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {\n    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },\n  });\n  const { data } = await supabase.auth.getUser();\n  if (!data.user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });\n  return NextResponse.next();\n}\nexport const config = { matcher: ["/((?!_next/static|_next/image|.*\\\\.(?:csv|pdf|png)$).*)"] };\n',
    "package.json":
      '{"name": "f-twin-extension-list", "private": true, "dependencies": {"next": "15.5.25", "@supabase/supabase-js": "2.49.0", "@supabase/ssr": "0.6.1", "next-auth": "4.24.11", "@simplewebauthn/server": "13.1.1", "react": "19.1.0"}}\n',
    "supabase/migrations/0001_init.sql":
      "create table public.invoices (id uuid primary key, org_id uuid, total numeric);\nalter table public.invoices enable row level security;\ncreate table public.users (id uuid primary key, email text, public_key text, counter int);\nalter table public.users enable row level security;\n",
    "tsconfig.json":
      '{ "compilerOptions": { "strict": true, "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
  },
  "g-percent5F-underscore-folder": {
    "app/%5Finternal/stats/route.ts":
      'import { admin } from "@/lib/admin";\nexport async function GET() {\n  const { data } = await admin.from("invoices").select("*");\n  return Response.json(data);\n}\n',
    "lib/admin.ts":
      'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n',
    "middleware.ts":
      'import { createServerClient } from "@supabase/ssr";\nimport { NextResponse, type NextRequest } from "next/server";\nexport async function middleware(request: NextRequest) {\n  const { pathname } = request.nextUrl;\n  if (pathname.startsWith("/_")) return NextResponse.next();\n  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {\n    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },\n  });\n  const { data } = await supabase.auth.getUser();\n  if (!data.user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });\n  return NextResponse.next();\n}\n',
    "package.json":
      '{"name": "g-percent5F-underscore-folder", "private": true, "dependencies": {"next": "15.5.25", "@supabase/supabase-js": "2.49.0", "@supabase/ssr": "0.6.1", "next-auth": "4.24.11", "@simplewebauthn/server": "13.1.1", "react": "19.1.0"}}\n',
    "supabase/migrations/0001_init.sql":
      "create table public.invoices (id uuid primary key, org_id uuid, total numeric);\nalter table public.invoices enable row level security;\ncreate table public.users (id uuid primary key, email text, public_key text, counter int);\nalter table public.users enable row level security;\n",
    "tsconfig.json":
      '{ "compilerOptions": { "strict": true, "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
  },
  "h-open-range-pnpm-lock": {
    "app/api/reports/[period]/route.ts":
      'import { admin } from "@/lib/admin";\nexport async function GET(_req: Request, { params }: { params: Promise<{ period: string }> }) {\n  const { period } = await params;\n  const { data } = await admin.from("invoices").select("*");\n  return Response.json({ period, data });\n}\n',
    "lib/admin.ts":
      'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n',
    "middleware.ts":
      'import { createServerClient } from "@supabase/ssr";\nimport { NextResponse, type NextRequest } from "next/server";\nexport async function middleware(request: NextRequest) {\n  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {\n    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },\n  });\n  const { data } = await supabase.auth.getUser();\n  if (!data.user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });\n  return NextResponse.next();\n}\nexport const config = { matcher: ["/api/:path*"] };\n',
    "package.json":
      '{"name": "h-open-range-pnpm-lock", "private": true, "dependencies": {"next": ">=15.5.18", "@supabase/supabase-js": "2.49.0", "@supabase/ssr": "0.6.1", "next-auth": "4.24.11", "@simplewebauthn/server": "13.1.1", "react": "19.1.0"}}\n',
    "pnpm-lock.yaml":
      "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      next:\n        specifier: '>=15.5.18'\n        version: 16.1.0(react@19.1.0)\n",
    "supabase/migrations/0001_init.sql":
      "create table public.invoices (id uuid primary key, org_id uuid, total numeric);\nalter table public.invoices enable row level security;\ncreate table public.users (id uuid primary key, email text, public_key text, counter int);\nalter table public.users enable row level security;\n",
    "tsconfig.json":
      '{ "compilerOptions": { "strict": true, "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
  },
  "h-twin-caret-range": {
    "app/api/reports/[period]/route.ts":
      'import { admin } from "@/lib/admin";\nexport async function GET(_req: Request, { params }: { params: Promise<{ period: string }> }) {\n  const { period } = await params;\n  const { data } = await admin.from("invoices").select("*");\n  return Response.json({ period, data });\n}\n',
    "lib/admin.ts":
      'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n',
    "middleware.ts":
      'import { createServerClient } from "@supabase/ssr";\nimport { NextResponse, type NextRequest } from "next/server";\nexport async function middleware(request: NextRequest) {\n  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {\n    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },\n  });\n  const { data } = await supabase.auth.getUser();\n  if (!data.user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });\n  return NextResponse.next();\n}\nexport const config = { matcher: ["/api/:path*"] };\n',
    "package.json":
      '{"name": "h-twin-caret-range", "private": true, "dependencies": {"next": "^16.1.0", "@supabase/supabase-js": "2.49.0", "@supabase/ssr": "0.6.1", "next-auth": "4.24.11", "@simplewebauthn/server": "13.1.1", "react": "19.1.0"}}\n',
    "supabase/migrations/0001_init.sql":
      "create table public.invoices (id uuid primary key, org_id uuid, total numeric);\nalter table public.invoices enable row level security;\ncreate table public.users (id uuid primary key, email text, public_key text, counter int);\nalter table public.users enable row level security;\n",
    "tsconfig.json":
      '{ "compilerOptions": { "strict": true, "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
  },
  "w1-passkey-helper-early-return": {
    "app/api/passkey/login/route.ts":
      'import { admin } from "@/lib/admin";\nimport { requirePasskey } from "@/lib/passkey";\nexport async function POST(req: Request) {\n  const body = await req.json();\n  await requirePasskey(body);\n  const { data } = await admin.from("invoices").select("*");\n  return Response.json(data);\n}\n',
    "lib/admin.ts":
      'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n',
    "lib/passkey.ts":
      'import { verifyAuthenticationResponse } from "@simplewebauthn/server";\nimport { admin } from "@/lib/admin";\nexport async function requirePasskey(body: any) {\n  // Clients that remembered this device send no assertion.\n  if (!body.response) return null;\n  const { data: user } = await admin.from("users").select("id, public_key, counter").eq("id", body.userId).single();\n  const verification = await verifyAuthenticationResponse({\n    response: body.response,\n    expectedChallenge: body.challenge,\n    expectedOrigin: "https://example.com",\n    expectedRPID: "example.com",\n    credential: { id: body.response?.id, publicKey: Buffer.from(user.public_key, "base64"), counter: user.counter },\n  });\n  if (!verification.verified) throw new Error("passkey rejected");\n  return user;\n}\n',
    "package.json":
      '{"name": "w1-passkey-helper-early-return", "private": true, "dependencies": {"next": "15.5.25", "@supabase/supabase-js": "2.49.0", "@supabase/ssr": "0.6.1", "next-auth": "4.24.11", "@simplewebauthn/server": "13.1.1", "react": "19.1.0"}}\n',
    "supabase/migrations/0001_init.sql":
      "create table public.invoices (id uuid primary key, org_id uuid, total numeric);\nalter table public.invoices enable row level security;\ncreate table public.users (id uuid primary key, email text, public_key text, counter int);\nalter table public.users enable row level security;\n",
    "tsconfig.json":
      '{ "compilerOptions": { "strict": true, "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
  },
  "w1-twin-no-early-return": {
    "app/api/passkey/login/route.ts":
      'import { admin } from "@/lib/admin";\nimport { requirePasskey } from "@/lib/passkey";\nexport async function POST(req: Request) {\n  const body = await req.json();\n  await requirePasskey(body);\n  const { data } = await admin.from("invoices").select("*");\n  return Response.json(data);\n}\n',
    "lib/admin.ts":
      'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n',
    "lib/passkey.ts":
      'import { verifyAuthenticationResponse } from "@simplewebauthn/server";\nimport { admin } from "@/lib/admin";\nexport async function requirePasskey(body: any) {\n  const { data: user } = await admin.from("users").select("id, public_key, counter").eq("id", body.userId).single();\n  const verification = await verifyAuthenticationResponse({\n    response: body.response,\n    expectedChallenge: body.challenge,\n    expectedOrigin: "https://example.com",\n    expectedRPID: "example.com",\n    credential: { id: body.response?.id, publicKey: Buffer.from(user.public_key, "base64"), counter: user.counter },\n  });\n  if (!verification.verified) throw new Error("passkey rejected");\n  return user;\n}\n',
    "package.json":
      '{"name": "w1-twin-no-early-return", "private": true, "dependencies": {"next": "15.5.25", "@supabase/supabase-js": "2.49.0", "@supabase/ssr": "0.6.1", "next-auth": "4.24.11", "@simplewebauthn/server": "13.1.1", "react": "19.1.0"}}\n',
    "supabase/migrations/0001_init.sql":
      "create table public.invoices (id uuid primary key, org_id uuid, total numeric);\nalter table public.invoices enable row level security;\ncreate table public.users (id uuid primary key, email text, public_key text, counter int);\nalter table public.users enable row level security;\n",
    "tsconfig.json":
      '{ "compilerOptions": { "strict": true, "baseUrl": ".", "paths": { "@/*": ["./*"] } } }\n',
  },
};
