import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import type { ProjectModel, RouteHandler } from "./model.js";
import { parseProject } from "./parse-project.js";

/**
 * A development-only route returns first thing in a production build. The condition is read in a
 * few plain shapes only; every other shape keeps the finding.
 */

const ADMIN = `import { createClient } from "@supabase/supabase-js";
export const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
`;

function model(files: Record<string, string>): ProjectModel {
  const dir = mkdtempSync(join(tmpdir(), "auditai-prodexit-"));
  const all: Record<string, string> = {
    "package.json": JSON.stringify({ dependencies: { next: "16.2.11" } }),
    "tsconfig.json": JSON.stringify({ compilerOptions: { paths: { "@/*": ["./*"] } } }),
    "lib/admin.ts": ADMIN,
    ...files,
  };
  for (const [rel, text] of Object.entries(all)) {
    mkdirSync(join(dir, dirname(rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return parseProject(dir);
}

function entry(m: ProjectModel, e: string): RouteHandler {
  const r = m.routes.find((x) => x.entry === e);
  if (!r) throw new Error(`no entry ${e}: ${m.routes.map((x) => x.entry).join(", ")}`);
  return r;
}

describe("development-only routes", () => {
  const route = (first: string, helper = ""): RouteHandler =>
    entry(
      model({
        "lib/dev.ts": `export function devAllowedElsewhere() {
  if (process.env.NODE_ENV === "production") return false;
  return true;
}
`,
        "app/api/seed/route.ts": `import { admin } from "@/lib/admin";
import { devAllowedElsewhere } from "@/lib/dev";
${
  helper ||
  `function devAllowed() {
  if (process.env.NODE_ENV === "production") return false;
  return process.env.ALLOW_SEED === "1";
}`
}
export async function POST() {
  ${first}
  await admin.from("users").insert({ email: "a@b.c" });
  return Response.json({ ok: true });
}
`,
      }),
      "POST /api/seed",
    );

  it("records a handler that returns first thing in production", () => {
    expect(
      route(
        `if (process.env.NODE_ENV === "production") return new Response(null, { status: 404 });`,
      ).productionExit,
    ).toBeDefined();
    expect(
      route(`if (!devAllowed()) return new Response(null, { status: 404 });`).productionExit,
    ).toBeDefined();
    expect(
      route(`if (process.env.NODE_ENV !== "development") { throw new Error("dev only"); }`)
        .productionExit,
    ).toBeDefined();
  });

  it("does not record one that is only disabled in development", () => {
    expect(
      route(
        `if (process.env.NODE_ENV === "development") return new Response(null, { status: 404 });`,
      ).productionExit,
    ).toBeUndefined();
    expect(
      route(`if (process.env.ALLOW_SEED !== "1") return new Response(null, { status: 404 });`)
        .productionExit,
    ).toBeUndefined();
  });

  it("does not read a helper it cannot see whole: imported, reassigned, async or deciding later", () => {
    const exit = `if (!devAllowed()) return new Response(null, { status: 404 });`;
    expect(
      route(`if (!devAllowedElsewhere()) return new Response(null, { status: 404 });`)
        .productionExit,
    ).toBeUndefined();
    expect(
      route(
        exit,
        `let devAllowed = function () { if (process.env.NODE_ENV === "production") return false; return true; };`,
      ).productionExit,
    ).toBeUndefined();
    expect(
      route(
        exit,
        `function devAllowed() { if (process.env.NODE_ENV === "production") return false; return true; }
if (process.env.PREVIEW) { (globalThis as any).x = devAllowed; }`,
      ).productionExit,
    ).toBeUndefined();
    expect(
      route(
        exit,
        `function devAllowed() { const on = process.env.ALLOW === "1"; if (process.env.NODE_ENV === "production") return false; return on; }`,
      ).productionExit,
    ).toBeUndefined();
  });

  it("does not record a production branch that does anything but answer", () => {
    expect(
      route(
        `if (process.env.NODE_ENV === "production") { await admin.from("users").delete(); return new Response(null, { status: 404 }); }`,
      ).productionExit,
    ).toBeUndefined();
    expect(
      route(`if (process.env.NODE_ENV === "production") return admin.from("users").select("*");`)
        .productionExit,
    ).toBeUndefined();
  });
});
