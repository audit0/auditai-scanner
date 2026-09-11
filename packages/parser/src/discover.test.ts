import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { discoverFiles, globToRegExp, isIgnored } from "./discover.js";

describe("globToRegExp", () => {
  it("matches directories, nested paths and single segments", () => {
    const evals = [globToRegExp("evals/**")];
    expect(isIgnored("evals/fixtures/001/app/route.ts", evals)).toBe(true);
    expect(isIgnored("evals", evals)).toBe(true);
    expect(isIgnored("apps/web/app/route.ts", evals)).toBe(false);
    const ts = [globToRegExp("**/*.test.ts")];
    expect(isIgnored("packages/core/src/a.test.ts", ts)).toBe(true);
    expect(isIgnored("packages/core/src/a.ts", ts)).toBe(false);
    const seg = [globToRegExp("apps/*/scripts")];
    expect(isIgnored("apps/web/scripts/x.ts", seg)).toBe(true);
    expect(isIgnored("apps/web/app/scripts/x.ts", seg)).toBe(false);
  });
});

describe("discoverFiles with ignore globs", () => {
  it("skips ignored trees entirely", () => {
    const dir = mkdtempSync(join(tmpdir(), "auditai-disc-"));
    mkdirSync(join(dir, "app/api"), { recursive: true });
    mkdirSync(join(dir, "evals/fixtures/x/app"), { recursive: true });
    writeFileSync(join(dir, "app/api/route.ts"), "export const GET = () => new Response('ok');");
    writeFileSync(
      join(dir, "evals/fixtures/x/app/route.ts"),
      "export const GET = () => new Response('bad');",
    );
    expect(discoverFiles(dir).source).toEqual([
      "app/api/route.ts",
      "evals/fixtures/x/app/route.ts",
    ]);
    expect(discoverFiles(dir, [], ["evals/**"]).source).toEqual(["app/api/route.ts"]);
  });
});
