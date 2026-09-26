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
 * R7, `service-role-query-without-authentication`, asks whether anyone on the internet reaches the
 * privileged query. A middleware is not taken as the answer: the round-8 middleware gate was cut in
 * its third review (every round found another way around it), so R7 reports the handler whatever
 * the middleware does, as before the round. The shapes the gate once accepted stay here, now
 * expecting the finding, next to the counterexamples that showed why.
 */

const R7 = "supabase.service-role-query-without-authentication";

const ADMIN = `import { createClient } from "@supabase/supabase-js";
export const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
`;

const ROUTE = `import { admin } from "@/lib/admin";
export async function GET() {
  const { data } = await admin.from("invoices").select("*");
  return Response.json(data);
}
`;

const MIDDLEWARE = (
  enforce: boolean,
): string => `import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";
export async function middleware(request: NextRequest) {
  let response = NextResponse.next({ request });
  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: { getAll: () => request.cookies.getAll(), setAll: () => { response = NextResponse.next({ request }); } },
  });
  const { data: { user } } = await supabase.auth.getUser();
  ${enforce ? `if (!user && !request.nextUrl.pathname.startsWith("/login")) return NextResponse.redirect(new URL("/login", request.url));` : ""}
  return response;
}
export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
`;

function scan(files: Record<string, string>): Finding[] {
  const dir = mkdtempSync(join(tmpdir(), "auditai-r7-mw-"));
  const all: Record<string, string> = {
    "package.json": JSON.stringify({ dependencies: { next: "15.3.1" } }),
    "tsconfig.json": JSON.stringify({ compilerOptions: { paths: { "@/*": ["./*"] } } }),
    "lib/admin.ts": ADMIN,
    "supabase/migrations/0001_init.sql": `create table public.invoices (id uuid primary key, org_id uuid, total numeric);
alter table public.invoices enable row level security;
create table public.users (id uuid primary key, email text);
alter table public.users enable row level security;
`,
    ...files,
  };
  for (const [rel, text] of Object.entries(all)) {
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

const r7 = (fs: Finding[]): Finding[] => fs.filter((f) => f.ruleId === R7);

describe("R7 behind a middleware", () => {
  it("still reports the route when the middleware redirects every unauthenticated request", () => {
    expect(
      r7(scan({ "app/api/invoices/route.ts": ROUTE, "middleware.ts": MIDDLEWARE(true) })),
    ).toHaveLength(1);
  });

  it("still reports the route when the middleware only refreshes the session", () => {
    expect(
      r7(scan({ "app/api/invoices/route.ts": ROUTE, "middleware.ts": MIDDLEWARE(false) })),
    ).toHaveLength(1);
  });

  it("still reports the route when there is no middleware at all", () => {
    expect(r7(scan({ "app/api/invoices/route.ts": ROUTE }))).toHaveLength(1);
  });
});

describe("storage behind a middleware", () => {
  const FILES = `import { admin } from "@/lib/admin";
export async function GET(_req: Request, { params }: { params: { name: string } }) {
  const { data } = await admin.storage.from("documents").download(params.name);
  return new Response(data);
}
`;
  const S1 = "supabase.storage-object-access-without-owner-scope";

  it("leaves a caller-supplied storage path to R7 with or without an enforcing middleware", () => {
    const behind = scan({
      "app/api/files/[name]/route.ts": FILES,
      "middleware.ts": MIDDLEWARE(true),
    });
    expect(r7(behind)).toHaveLength(1);
    expect(behind.filter((f) => f.ruleId === S1)).toEqual([]);
    const open = scan({
      "app/api/files/[name]/route.ts": FILES,
      "middleware.ts": MIDDLEWARE(false),
    });
    expect(r7(open)).toHaveLength(1);
    expect(open.filter((f) => f.ruleId === S1)).toEqual([]);
  });
});

describe("R1 behind a middleware", () => {
  const R1 = "supabase.service-role-object-access-without-tenant-scope";
  const BY_ID = `import { admin } from "@/lib/admin";
export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const { data } = await admin.from("invoices").select("*").eq("id", params.id).single();
  return Response.json(data);
}
`;

  it("says nobody authenticates, middleware or not: the middleware is not taken as a login", () => {
    const behind = scan({
      "app/api/invoices/[id]/route.ts": BY_ID,
      "middleware.ts": MIDDLEWARE(true),
    }).filter((f) => f.ruleId === R1);
    expect(behind).toHaveLength(1);
    expect(behind[0]?.title.startsWith("Unauthenticated ")).toBe(true);

    const open = scan({
      "app/api/invoices/[id]/route.ts": BY_ID,
      "middleware.ts": MIDDLEWARE(false),
    }).filter((f) => f.ruleId === R1);
    expect(open).toHaveLength(1);
    expect(open[0]?.title.startsWith("Unauthenticated ")).toBe(true);
    expect(open[0]?.severity).toBe(behind[0]?.severity);
  });
});

describe("R7 on a development-only route", () => {
  const SEED = (guard: string): string => `import { admin } from "@/lib/admin";
export async function POST() {
  ${guard}
  await admin.from("users").insert({ email: "test@example.com" });
  return Response.json({ ok: true });
}
`;

  it("stays silent when the handler returns first thing in a production build", () => {
    const fs = scan({
      "app/api/seed/route.ts": SEED(
        `if (process.env.NODE_ENV === "production") return new Response(null, { status: 404 });`,
      ),
    });
    expect(r7(fs)).toEqual([]);
  });

  it("still reports it when the guard is a flag somebody can leave on", () => {
    const fs = scan({
      "app/api/seed/route.ts": SEED(
        `if (process.env.ENABLE_SEED !== "true") return new Response(null, { status: 404 });`,
      ),
    });
    expect(r7(fs)).toHaveLength(1);
  });
});

/**
 * Counterexamples built by the round-8 review (scratchpad verify-W4, cx1 to cx6): each project has a
 * service-role query that an anonymous caller reaches, and each once slipped past the gate. R7 must
 * report every one of them.
 */
describe("R7 on the review's counterexamples", () => {
  const PKG = JSON.stringify({
    dependencies: {
      next: "15.5.25",
      "@supabase/supabase-js": "2.49.0",
      "@supabase/ssr": "0.6.1",
      "next-auth": "4.24.11",
      "@simplewebauthn/server": "13.1.1",
      react: "19.1.0",
    },
  });
  const SUPABASE_GATE = (
    open: string,
    matcher = "",
  ): string => `import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  if (${open}) return NextResponse.next();
  const response = NextResponse.next({ request });
  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },
  });
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.redirect(new URL("/login", request.url));
  return response;
}
${matcher}`;
  const NEXTAUTH_GATE = (options: string): string => `import { getToken } from "next-auth/jwt";
import { NextResponse, type NextRequest } from "next/server";

export async function middleware(req: NextRequest) {
  const token = await getToken(${options});
  if (!token) return NextResponse.json({ error: "Authentication required" }, { status: 401 });
  return NextResponse.next();
}
export const config = { matcher: ["/api/:path*"] };
`;

  it("cx1: a passkey check that only runs when the body asks for it", () => {
    const fs = scan({
      "package.json": PKG,
      "app/api/passkey/login/route.ts": `import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import { admin } from "@/lib/admin";

export async function POST(req: Request) {
  const body = await req.json();
  const verification = await verifyAuthenticationResponse({
    response: body.response,
    expectedChallenge: body.challenge,
    expectedOrigin: "https://example.com",
    expectedRPID: "example.com",
    credential: { id: body.response.id, publicKey: new Uint8Array(), counter: 0 },
  });
  if (body.strict) {
    if (!verification.verified) return Response.json({ error: "bad" }, { status: 401 });
  }
  const { data } = await admin.from("invoices").select("*");
  return Response.json(data);
}
`,
    });
    expect(r7(fs).map((f) => f.entrypoints[0])).toEqual(["POST /api/passkey/login"]);
  });

  it("cx2: getToken() with a decode that reads the token without verifying it", () => {
    const fs = scan({
      "package.json": PKG,
      "app/api/invoices/route.ts": ROUTE,
      "middleware.ts": NEXTAUTH_GATE(`{
    req,
    secret: process.env.NEXTAUTH_SECRET,
    // Shared with the mobile app: the token is a plain base64 JSON blob, not a signed JWE.
    decode: async ({ token }) => (token ? JSON.parse(atob(token)) : null),
  }`),
    });
    expect(r7(fs).map((f) => f.entrypoints[0])).toEqual(["GET /api/invoices"]);
  });

  it("cx3: getToken() whose secret falls back to a literal anyone can read", () => {
    const fs = scan({
      "package.json": PKG,
      "app/api/invoices/route.ts": ROUTE,
      "middleware.ts": NEXTAUTH_GATE(
        `{ req, secret: process.env.NEXTAUTH_SECRET || "dev-secret-change-me" }`,
      ),
    });
    expect(r7(fs).map((f) => f.entrypoints[0])).toEqual(["GET /api/invoices"]);
  });

  it("cx4: an intercepting page, served under the URL of the route it intercepts", () => {
    const fs = scan({
      "package.json": PKG,
      "middleware.ts": SUPABASE_GATE(
        `pathname === "/" || pathname.startsWith("/photo/") || pathname.startsWith("/login")`,
      ),
      "app/feed/layout.tsx": `export default function FeedLayout({ children, modal }: { children: React.ReactNode; modal: React.ReactNode }) {
  return <>{children}{modal}</>;
}
`,
      "app/feed/page.tsx": "export default function Feed() { return <p>feed</p>; }\n",
      "app/photo/[id]/page.tsx": `export default async function Photo({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <p>photo {id}</p>;
}
`,
      "app/feed/@modal/(..)photo/[id]/page.tsx": `import { admin } from "@/lib/admin";
export default async function PhotoModal({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { data } = await admin.from("invoices").select("*");
  return <pre>{id}{JSON.stringify(data)}</pre>;
}
`,
    });
    expect(r7(fs)).toHaveLength(1);
  });

  const STATS_OPEN = `pathname === "/" || pathname === "/stats" || pathname.startsWith("/login")`;

  it("cx5a (control): a literal rewrite from an open path onto the route", () => {
    const fs = scan({
      "package.json": PKG,
      "app/api/invoices/route.ts": ROUTE,
      "middleware.ts": SUPABASE_GATE(STATS_OPEN),
      "next.config.mjs": `export default {
  async rewrites() {
    return [{ source: "/stats", destination: "/api/invoices" }];
  },
};
`,
    });
    expect(r7(fs).map((f) => f.entrypoints[0])).toEqual(["GET /api/invoices"]);
  });

  it("cx5b: the rewrite onto the route comes from an imported list spread into the array", () => {
    const fs = scan({
      "package.json": PKG,
      "app/api/invoices/route.ts": ROUTE,
      "middleware.ts": SUPABASE_GATE(STATS_OPEN),
      "legacy-rewrites.mjs": `export const legacyRewrites = [{ source: "/stats", destination: "/api/invoices" }];\n`,
      "next.config.mjs": `import { legacyRewrites } from "./legacy-rewrites.mjs";
export default {
  async rewrites() {
    return [{ source: "/blog/:path*", destination: "https://blog.example.com/:path*" }, ...legacyRewrites];
  },
};
`,
    });
    expect(r7(fs).map((f) => f.entrypoints[0])).toEqual(["GET /api/invoices"]);
  });

  it("cx5c: the rewrite's destination is held in a constant", () => {
    const fs = scan({
      "package.json": PKG,
      "app/api/invoices/route.ts": ROUTE,
      "middleware.ts": SUPABASE_GATE(STATS_OPEN),
      "next.config.mjs": `const STATS_API = "/api/invoices";
export default {
  async rewrites() {
    return [
      { source: "/blog/:path*", destination: "https://blog.example.com/:path*" },
      { source: "/stats", destination: STATS_API },
    ];
  },
};
`,
    });
    expect(r7(fs).map((f) => f.entrypoints[0])).toEqual(["GET /api/invoices"]);
  });

  const MEMO_GATE = (
    mobileName: string,
  ): string => `import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

function isPresent(value: unknown): boolean {
  return !!value;
}

export async function middleware(request: NextRequest) {
  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },
  });
  const { data: { user } } = await supabase.auth.getUser();
  if (request.headers.get("x-client") !== "mobile") {
    const token = user;
    if (!isPresent(token)) return NextResponse.redirect(new URL("/login", request.url));
    return NextResponse.next();
  }
  // Mobile clients: "the bearer is checked by the API" (it is not).
  const ${mobileName} = request.headers.get("authorization");
  if (!isPresent(${mobileName})) return NextResponse.json({ error: "missing token" }, { status: 401 });
  return NextResponse.next();
}
export const config = { matcher: ["/api/:path*"] };
`;

  it("cx6: one helper called on the session user in one branch and on a raw header in another", () => {
    for (const name of ["token", "bearer"]) {
      const fs = scan({
        "package.json": PKG,
        "app/api/invoices/route.ts": ROUTE,
        "middleware.ts": MEMO_GATE(name),
      });
      expect(r7(fs).map((f) => f.entrypoints[0])).toEqual(["GET /api/invoices"]);
    }
  });
});

/**
 * Counterexamples built by the second round-8 review (scratchpad verify-W4-r2, cx7 to cx14d): each
 * project has a service-role query that an anonymous caller reaches, and each slipped past the
 * branch as it stood. R7 must report every one of them. Each sits next to the twin it is easily
 * mistaken for, which R7 must leave alone.
 */
describe("R7 on the second review's counterexamples", () => {
  const PKG = JSON.stringify({
    dependencies: {
      next: "15.5.25",
      "@supabase/supabase-js": "2.49.0",
      "@supabase/ssr": "0.6.1",
      "next-auth": "4.24.11",
      "@simplewebauthn/server": "13.1.1",
      react: "19.1.0",
    },
  });
  const entries = (fs: Finding[]): string[] => r7(fs).map((f) => f.entrypoints[0] ?? "");
  const withPkg = (files: Record<string, string>): Finding[] =>
    scan({ "package.json": PKG, ...files });

  // --- development-only routes (productionExitOf) ---------------------------------------------

  it("cx7: the query runs inside the production branch (mock in development, real in production)", () => {
    const fs = withPkg({
      "app/api/invoices/route.ts": `import { admin } from "@/lib/admin";
const MOCK = [{ id: "00000000-0000-0000-0000-000000000000", org_id: null, total: 10 }];
export async function GET() {
  if (process.env.NODE_ENV === "production") {
    const { data } = await admin.from("invoices").select("*");
    return Response.json(data);
  }
  return Response.json(MOCK);
}
`,
    });
    expect(entries(fs)).toEqual(["GET /api/invoices"]);
  });

  it("cx7b: the production branch returns a helper that runs the query", () => {
    const fs = withPkg({
      "app/api/invoices/route.ts": `import { admin } from "@/lib/admin";
async function listInvoices() {
  const { data } = await admin.from("invoices").select("*");
  return Response.json(data);
}
export async function GET() {
  if (process.env.NODE_ENV === "production") return listInvoices();
  return Response.json([]);
}
`,
    });
    expect(entries(fs)).toEqual(["GET /api/invoices"]);
  });

  it("cx7 (more): a production branch that does anything before it answers is not an exit", () => {
    const fs = withPkg({
      "app/api/seed/route.ts": `import { admin } from "@/lib/admin";
export async function POST() {
  if (process.env.NODE_ENV === "production") {
    await admin.from("users").insert({ email: "prod@example.com" });
    return Response.json({ error: "disabled" }, { status: 403 });
  }
  await admin.from("users").insert({ email: "test@example.com" });
  return Response.json({ ok: true });
}
`,
    });
    expect(entries(fs)).toEqual(["POST /api/seed"]);
  });

  it("cx7 twin: a production branch that only answers, with or without a block, is an exit", () => {
    for (const guard of [
      `if (process.env.NODE_ENV === "production") { return Response.json({ error: "Not found" }, { status: 404 }); }`,
      `if (process.env.NODE_ENV === "production") return NextResponse.json({ error: "Forbidden" }, { status: 403 });`,
      `if (process.env.NODE_ENV === "production") throw new Error("development only");`,
    ]) {
      const fs = withPkg({
        "app/api/seed/route.ts": `import { NextResponse } from "next/server";
import { admin } from "@/lib/admin";
export async function POST() {
  ${guard}
  await admin.from("users").insert({ email: "test@example.com" });
  return NextResponse.json({ ok: true });
}
`,
      });
      expect(entries(fs)).toEqual([]);
    }
  });

  // --- getToken() secret -------------------------------------------------------------------------

  const TOKEN_MW = (
    head: string,
    secret: string,
  ): string => `import { getToken } from "next-auth/jwt";
import { NextResponse, type NextRequest } from "next/server";
${head}
export async function middleware(req: NextRequest) {
  const token = await getToken({ req, secret: ${secret} });
  if (!token) return NextResponse.json({ error: "Authentication required" }, { status: 401 });
  return NextResponse.next();
}
export const config = { matcher: ["/api/:path*"] };
`;

  it("cx8: the secret is a literal held in a constant", () => {
    const fs = withPkg({
      "app/api/invoices/route.ts": ROUTE,
      "middleware.ts": TOKEN_MW(`const SECRET = "dev-secret-change-me";`, "SECRET"),
    });
    expect(entries(fs)).toEqual(["GET /api/invoices"]);
  });

  it("cx8b: the secret is imported from a module where it falls back to a literal", () => {
    const fs = withPkg({
      "app/api/invoices/route.ts": ROUTE,
      "lib/env.ts": `export const AUTH_SECRET = process.env.NEXTAUTH_SECRET || "dev-secret-change-me";\n`,
      "middleware.ts": TOKEN_MW(`import { AUTH_SECRET } from "@/lib/env";`, "AUTH_SECRET"),
    });
    expect(entries(fs)).toEqual(["GET /api/invoices"]);
  });

  it("cx8c: the env read falls back to a constant that holds a literal", () => {
    const fs = withPkg({
      "app/api/invoices/route.ts": ROUTE,
      "middleware.ts": TOKEN_MW(
        `const DEFAULT_SECRET = "dev-secret-change-me";`,
        "process.env.NEXTAUTH_SECRET ?? DEFAULT_SECRET",
      ),
    });
    expect(entries(fs)).toEqual(["GET /api/invoices"]);
  });

  it("cx8d: the secret is a property of an object literal", () => {
    const fs = withPkg({
      "app/api/invoices/route.ts": ROUTE,
      "middleware.ts": TOKEN_MW(
        `const authConfig = { secret: "dev-secret-change-me" };`,
        "authConfig.secret",
      ),
    });
    expect(entries(fs)).toEqual(["GET /api/invoices"]);
  });

  it("cx8 twin (gate cut, still reported): an env read, directly, in a constant or in an imported constant", () => {
    for (const [head, secret, extra] of [
      ["", "process.env.NEXTAUTH_SECRET", {}],
      ["const SECRET = process.env.NEXTAUTH_SECRET!;", "SECRET", {}],
      [
        `import { AUTH_SECRET } from "@/lib/env";`,
        "AUTH_SECRET",
        { "lib/env.ts": "export const AUTH_SECRET = process.env.NEXTAUTH_SECRET;\n" },
      ],
    ] as const) {
      const fs = withPkg({
        "app/api/invoices/route.ts": ROUTE,
        "middleware.ts": TOKEN_MW(head, secret),
        ...extra,
      });
      expect(entries(fs)).toHaveLength(1);
    }
  });

  // --- a rewrite in the middleware onto the route ------------------------------------------------

  const STATS_MW = (
    stats: string,
    head = "",
  ): string => `import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";
${head}
export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  if (pathname === "/stats") {
    const url = request.nextUrl.clone();
    ${stats}
    return NextResponse.rewrite(url);
  }
  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },
  });
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });
  return NextResponse.next();
}
export const config = { matcher: ["/stats", "/api/:path*"] };
`;

  it("cx9: a helper points the cloned URL at the route", () => {
    const fs = withPkg({
      "app/api/invoices/route.ts": ROUTE,
      "middleware.ts": STATS_MW(
        `pointTo(url, "/api/invoices");`,
        `function pointTo(url: URL, target: string) {
  url.pathname = target;
}`,
      ),
    });
    expect(entries(fs)).toEqual(["GET /api/invoices"]);
  });

  it("cx9b: the pathname is assigned through an element access", () => {
    const fs = withPkg({
      "app/api/invoices/route.ts": ROUTE,
      "middleware.ts": STATS_MW(`url["pathname"] = "/api/invoices";`),
    });
    expect(entries(fs)).toEqual(["GET /api/invoices"]);
  });

  it("cx9c: the pathname is assigned through an alias of the clone", () => {
    const fs = withPkg({
      "app/api/invoices/route.ts": ROUTE,
      "middleware.ts": STATS_MW(`const target = url;
    target.pathname = "/api/invoices";`),
    });
    expect(entries(fs)).toEqual(["GET /api/invoices"]);
  });

  it("cx9 (more): Object.assign or a compound assignment on the clone", () => {
    for (const stats of [
      `Object.assign(url, { pathname: "/api/invoices" });`,
      `url.pathname += "api/invoices";`,
    ]) {
      const fs = withPkg({ "app/api/invoices/route.ts": ROUTE, "middleware.ts": STATS_MW(stats) });
      expect(entries(fs)).toEqual(["GET /api/invoices"]);
    }
  });

  it("cx9 twin (gate cut, still reported): the clone is read, given search parameters, or pointed at a literal elsewhere", () => {
    for (const stats of [
      `url.searchParams.set("view", "public");`,
      `url.pathname = "/public-stats";`,
      `if (url.pathname.endsWith("/")) url.searchParams.delete("x");`,
    ]) {
      const fs = withPkg({ "app/api/invoices/route.ts": ROUTE, "middleware.ts": STATS_MW(stats) });
      expect(entries(fs)).toHaveLength(1);
    }
  });

  // --- dynamic segments ----------------------------------------------------------------------------

  const OPEN_MW = (
    open: string,
    head = "",
  ): string => `import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";
${head}
export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  if (${open}) return NextResponse.next();
  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },
  });
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });
  return NextResponse.next();
}
export const config = { matcher: ["/api/:path*"] };
`;

  const EXPORT_ROUTE = `import { admin } from "@/lib/admin";
export async function GET(_req: Request, { params }: { params: Promise<{ filename: string }> }) {
  const { filename } = await params;
  const { data } = await admin.from("invoices").select("*");
  return new Response(JSON.stringify(data), {
    headers: { "content-type": "application/json", "content-disposition": \`attachment; filename="\${filename}"\` },
  });
}
`;

  it("cx10: a static-file extension lets a dynamic segment through (/api/export/invoices.json)", () => {
    const fs = withPkg({
      "app/api/export/[filename]/route.ts": EXPORT_ROUTE,
      "middleware.ts": OPEN_MW(
        `/\\.(?:png|jpg|jpeg|svg|ico|webp|css|js|txt|xml|json|csv)$/.test(pathname)`,
      ),
    });
    expect(entries(fs)).toEqual(["GET /api/export/[filename]"]);
  });

  it("cx10b: a public suffix lets a dynamic segment through (/api/reports/health)", () => {
    const fs = withPkg({
      "app/api/reports/[period]/route.ts": ROUTE,
      "middleware.ts": OPEN_MW(
        "PUBLIC_SUFFIXES.some((s) => pathname.endsWith(s))",
        `const PUBLIC_SUFFIXES = ["/health", "/status"];`,
      ),
    });
    expect(entries(fs)).toEqual(["GET /api/reports/[period]"]);
  });

  it("cx10 twin (gate cut, still reported): public prefixes the route's own static prefix already decides", () => {
    for (const open of [
      `pathname.startsWith("/api/public/") || pathname === "/api/health"`,
      `["/login", "/api/auth"].some((p) => pathname.startsWith(p))`,
    ]) {
      const fs = withPkg({
        "app/api/export/[filename]/route.ts": EXPORT_ROUTE,
        "middleware.ts": OPEN_MW(open),
      });
      expect(entries(fs)).toHaveLength(1);
    }
  });

  // --- constant lists changed at run time ----------------------------------------------------------

  const LIST_MW = (head: string): string => OPEN_MW("PUBLIC_ROUTES.includes(pathname)", head);

  it("cx11: another module imports the public list and pushes the route onto it", () => {
    const fs = withPkg({
      "app/api/invoices/route.ts": ROUTE,
      "lib/public-routes.ts": `export const PUBLIC_ROUTES: string[] = ["/login", "/signup"];\n`,
      "lib/share-feature.ts": `import { PUBLIC_ROUTES as routes } from "./public-routes";
// Shared invoice links are public.
routes.push("/api/invoices");
`,
      "middleware.ts": LIST_MW(`import "@/lib/share-feature";
import { PUBLIC_ROUTES } from "@/lib/public-routes";`),
    });
    expect(entries(fs)).toEqual(["GET /api/invoices"]);
  });

  it("cx11b: an alias of the public list is pushed onto", () => {
    const fs = withPkg({
      "app/api/invoices/route.ts": ROUTE,
      "middleware.ts": LIST_MW(`const PUBLIC_ROUTES: string[] = ["/login", "/signup"];
const extra = PUBLIC_ROUTES;
extra.push("/api/invoices");`),
    });
    expect(entries(fs)).toEqual(["GET /api/invoices"]);
  });

  it("cx11 (more): the list is handed to a function, or pushed onto inside the middleware", () => {
    for (const [head, extra] of [
      [
        `const PUBLIC_ROUTES: string[] = ["/login", "/signup"];
function allow(list: string[], p: string) { list.push(p); }
allow(PUBLIC_ROUTES, "/api/invoices");`,
        {},
      ],
      [
        `import { PUBLIC_ROUTES } from "@/lib/public-routes";`,
        {
          "lib/public-routes.ts": `export const PUBLIC_ROUTES: string[] = ["/login", "/signup"];\n`,
          "lib/other.ts": `import { PUBLIC_ROUTES } from "./public-routes";\nexport const n = PUBLIC_ROUTES.length;\n`,
        },
      ],
    ] as const) {
      const fs = withPkg({
        "app/api/invoices/route.ts": ROUTE,
        "middleware.ts": LIST_MW(head),
        ...extra,
      });
      expect(entries(fs)).toEqual(["GET /api/invoices"]);
    }
  });

  it("cx11 twin (gate cut, still reported): a list only the middleware imports and only reads", () => {
    for (const [head, extra] of [
      [`const PUBLIC_ROUTES = ["/login", "/signup"];`, {}],
      [
        `import { PUBLIC_ROUTES } from "@/lib/public-routes";`,
        {
          "lib/public-routes.ts": `export const PUBLIC_ROUTES = ["/login", "/signup"] as const;\n`,
        },
      ],
    ] as const) {
      const fs = withPkg({
        "app/api/invoices/route.ts": ROUTE,
        "middleware.ts": LIST_MW(head),
        ...extra,
      });
      expect(entries(fs)).toHaveLength(1);
    }
  });

  // --- helpers bound with let ------------------------------------------------------------------------

  it("cx12: a let-bound helper the middleware reassigns when ?embed is present", () => {
    const fs = withPkg({
      "app/api/invoices/route.ts": ROUTE,
      "middleware.ts": `import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";
let isPublic = (_path: string): boolean => false;
export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  if (request.nextUrl.searchParams.has("embed")) isPublic = (p: string) => p.startsWith("/api/");
  if (isPublic(pathname)) return NextResponse.next();
  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },
  });
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });
  return NextResponse.next();
}
export const config = { matcher: ["/api/:path*"] };
`,
    });
    expect(entries(fs)).toEqual(["GET /api/invoices"]);
  });

  it("cx12 twin (gate cut, still reported): a const-bound or declared helper", () => {
    for (const head of [
      `const isPublic = (p: string): boolean => p === "/login";`,
      `function isPublic(p: string): boolean { return p === "/login"; }`,
    ]) {
      const fs = withPkg({
        "app/api/invoices/route.ts": ROUTE,
        "middleware.ts": OPEN_MW("isPublic(pathname)", head),
      });
      expect(entries(fs)).toHaveLength(1);
    }
  });

  // --- the getUser() result changed after the call ---------------------------------------------------

  const DEMO_MW = (mutation: string): string => `import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";
const DEMO_USER = { id: "demo" };
export async function middleware(request: NextRequest) {
  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: { getAll: () => request.cookies.getAll(), setAll: () => {} },
  });
  const { data } = await supabase.auth.getUser();
  ${mutation}
  if (!data.user) return NextResponse.json({ error: "Authentication required" }, { status: 401 });
  return NextResponse.next();
}
export const config = { matcher: ["/api/:path*"] };
`;

  it("cx13: a demo header writes a user into the getUser() result", () => {
    for (const mutation of [
      `if (request.headers.get("x-demo") === "1") (data as any).user = DEMO_USER;`,
      `if (request.headers.get("x-demo") === "1") data!.user = DEMO_USER;`,
      `if (request.headers.get("x-demo") === "1") Object.assign(data, { user: DEMO_USER });`,
      `request.headers.get("x-demo") === "1" && ((data as any).user ??= DEMO_USER);`,
    ]) {
      const fs = withPkg({
        "app/api/invoices/route.ts": ROUTE,
        "middleware.ts": DEMO_MW(mutation),
      });
      expect(entries(fs)).toEqual(["GET /api/invoices"]);
    }
  });

  it("cx13 twin (gate cut, still reported): the result is only read", () => {
    const fs = withPkg({
      "app/api/invoices/route.ts": ROUTE,
      "middleware.ts": DEMO_MW(
        `const demo = request.headers.get("x-demo") === "1" ? DEMO_USER : null;`,
      ),
    });
    expect(entries(fs)).toHaveLength(1);
  });

  // --- passkey logins ------------------------------------------------------------------------------

  /** The verification as the reviewer wrote it: the public key is not the stored one. */
  const VERIFY = (publicKey: string): string => `await verifyAuthenticationResponse({
    response: body.response,
    expectedChallenge: body.challenge,
    expectedOrigin: "https://example.com",
    expectedRPID: "example.com",
    credential: { id: body.response.id, publicKey: ${publicKey}, counter: 0 },
  })`;
  const STORED_KEY = 'Buffer.from(stored.public_key, "base64")';
  const LOOKUP = `const { data: stored } = await admin.from("users").select("public_key, counter").eq("id", body.userId).single();
  if (!stored) throw new Error("unknown credential");`;
  const PASSKEY_ROUTE = (
    body: string,
  ): string => `import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import { NextResponse } from "next/server";
import { admin } from "@/lib/admin";
import { requirePasskey } from "@/lib/passkey";
export async function POST(req: Request) {
  const body = await req.json();
  ${body}
  const { data } = await admin.from("invoices").select("*");
  return Response.json(data);
}
`;
  const PASSKEY_LIB = (
    fn: string,
  ): string => `import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import { admin } from "@/lib/admin";
${fn}
`;
  const REQUIRE = (
    key: string,
    lookup: string,
  ): string => `export async function requirePasskey(body: any) {
  ${lookup}
  const verification = ${VERIFY(key)};
  if (!verification.verified) throw new Error("passkey rejected");
}`;
  const CHECK = (
    key: string,
    lookup: string,
  ): string => `export async function requirePasskey(body: any) {
  ${lookup}
  let verification;
  try {
    verification = ${VERIFY(key)};
  } catch (e) {
    console.error(e);
    return null;
  }
  if (!verification.verified) throw new Error("passkey rejected");
  return verification;
}`;
  const R7_PASSKEY = ["POST /api/passkey/login"];

  it("cx14: the helper that verifies is called only when the body asks for it", () => {
    for (const [key, lookup] of [
      ["new Uint8Array()", ""],
      [STORED_KEY, LOOKUP],
    ]) {
      const fs = withPkg({
        "app/api/passkey/login/route.ts": PASSKEY_ROUTE(
          "if (body.strict) await requirePasskey(body);",
        ),
        "lib/passkey.ts": PASSKEY_LIB(REQUIRE(key, lookup)),
      });
      expect(entries(fs)).toEqual(R7_PASSKEY);
    }
  });

  it("cx14b: the helper's catch returns null and the handler ignores the result", () => {
    for (const [key, lookup] of [
      ["new Uint8Array()", ""],
      [STORED_KEY, LOOKUP],
    ]) {
      const fs = withPkg({
        "app/api/passkey/login/route.ts": PASSKEY_ROUTE("await requirePasskey(body);"),
        "lib/passkey.ts": PASSKEY_LIB(CHECK(key, lookup)),
      });
      expect(entries(fs)).toEqual(R7_PASSKEY);
    }
  });

  it("cx14c: the denial builds a redirect without returning it", () => {
    for (const [key, lookup] of [
      ["new Uint8Array()", ""],
      [STORED_KEY, LOOKUP],
    ]) {
      const fs = withPkg({
        "app/api/passkey/login/route.ts": PASSKEY_ROUTE(`${lookup}
  const verification = ${VERIFY(key)};
  if (!verification.verified) {
    NextResponse.redirect(new URL("/login?error=passkey", req.url));
  }`),
        "lib/passkey.ts": PASSKEY_LIB(""),
      });
      expect(entries(fs)).toEqual(R7_PASSKEY);
    }
  });

  it("cx14d: the public key comes from the request, so the caller signs with their own key", () => {
    const fs = withPkg({
      "app/api/passkey/login/route.ts": PASSKEY_ROUTE(`const verification = ${VERIFY(
        `Buffer.from(body.publicKey, "base64url")`,
      )};
  if (!verification.verified) return Response.json({ error: "bad" }, { status: 401 });`),
      "lib/passkey.ts": PASSKEY_LIB(""),
    });
    expect(entries(fs)).toEqual(R7_PASSKEY);
  });

  it("cx14 twins: a stored key, verified unconditionally, whose denial ends the request", () => {
    for (const [route, lib] of [
      // In the handler itself.
      [
        PASSKEY_ROUTE(`${LOOKUP}
  const verification = ${VERIFY(STORED_KEY)};
  if (!verification.verified) return NextResponse.redirect(new URL("/login?error=passkey", req.url));`),
        PASSKEY_LIB(""),
      ],
      // In a helper called unconditionally, which throws.
      [PASSKEY_ROUTE("await requirePasskey(body);"), PASSKEY_LIB(REQUIRE(STORED_KEY, LOOKUP))],
      // In a helper whose null the handler checks.
      [
        PASSKEY_ROUTE(
          `if (!(await requirePasskey(body))) return Response.json({ error: "bad" }, { status: 401 });`,
        ),
        PASSKEY_LIB(CHECK(STORED_KEY, LOOKUP)),
      ],
    ]) {
      const fs = withPkg({ "app/api/passkey/login/route.ts": route, "lib/passkey.ts": lib });
      expect(entries(fs)).toEqual([]);
    }
  });
});
