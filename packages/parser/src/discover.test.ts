import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  checkIgnoreGlobs,
  compileGlob,
  discoverFiles,
  GLOB_LIMITS,
  isIgnored,
  normalizeGlob,
  type PathMatcher,
} from "./discover.js";

function globs(...patterns: string[]): PathMatcher[] {
  return patterns.map((p) => {
    const m = compileGlob(p);
    if (!m) throw new Error(`glob ${p} rejected`);
    return m;
  });
}

describe("compileGlob", () => {
  it("matches directories, nested paths and single segments", () => {
    const evals = globs("evals/**");
    expect(isIgnored("evals/fixtures/001/app/route.ts", evals)).toBe(true);
    expect(isIgnored("evals", evals)).toBe(true);
    expect(isIgnored("apps/web/app/route.ts", evals)).toBe(false);
    const ts = globs("**/*.test.ts");
    expect(isIgnored("packages/core/src/a.test.ts", ts)).toBe(true);
    expect(isIgnored("a.test.ts", ts)).toBe(true);
    expect(isIgnored("packages/core/src/a.ts", ts)).toBe(false);
    const seg = globs("apps/*/scripts");
    expect(isIgnored("apps/web/scripts/x.ts", seg)).toBe(true);
    expect(isIgnored("apps/web/app/scripts/x.ts", seg)).toBe(false);
    const mid = globs("src/**/fixtures");
    expect(isIgnored("src/fixtures/a.ts", mid)).toBe(true);
    expect(isIgnored("src/a/b/fixtures/c/d.ts", mid)).toBe(true);
    expect(isIgnored("src/a/b/fixture/c.ts", mid)).toBe(false);
    const q = globs("./lib/v?/*.gen.ts");
    expect(isIgnored("lib/v1/api.gen.ts", q)).toBe(true);
    expect(isIgnored("lib/v10/api.gen.ts", q)).toBe(false);
    expect(isIgnored("lib/v1/api.ts", q)).toBe(false);
  });

  it("collapses repeated globstars without changing what they match", () => {
    expect(normalizeGlob("**/**/**/x")).toEqual({ glob: "**/x" });
    expect(normalizeGlob("evals/**/**/")).toEqual({ glob: "evals" });
    expect(normalizeGlob(`${"**/".repeat(10)}x`)).toEqual({ glob: "**/x" });
    const m = globs(`${"**/".repeat(10)}x`);
    expect(isIgnored("a/b/x/c.ts", m)).toBe(true);
    expect(isIgnored("a/b/y/c.ts", m)).toBe(false);
  });

  it("rejects globs over the complexity limits, with a warning", () => {
    for (const bad of [
      "a/**/b/**/c",
      "*a*b*c*d",
      "*/*/*/*",
      "x".repeat(GLOB_LIMITS.maxLength + 1),
      "",
      "./",
      "**",
      "**/**",
    ]) {
      const check = normalizeGlob(bad);
      expect(check.glob, bad).toBeNull();
      expect(check.warning, bad).toMatch(/^ignore glob .* rejected: /);
      expect(compileGlob(bad), bad).toBeNull();
    }
    // A run of stars inside a segment is one star, and says so.
    expect(normalizeGlob("lib/a**b")).toEqual({
      glob: "lib/a*b",
      warning: 'ignore glob "lib/a**b" read as "lib/a*b": "**" inside a segment matches like "*"',
    });
  });

  it("caps the number of globs per scan", () => {
    const many = Array.from({ length: GLOB_LIMITS.maxPatterns + 5 }, (_, i) => `dir${i}/**`);
    const r = checkIgnoreGlobs([...many, "a/**/b/**/c"]);
    expect(r.globs).toHaveLength(GLOB_LIMITS.maxPatterns);
    expect(r.warnings).toEqual([
      `6 ignore glob(s) dropped: at most ${GLOB_LIMITS.maxPatterns} are applied per scan`,
    ]);
  });

  it("matches worst-case segments in linear-ish time", () => {
    // Three stars in one segment against a 250-character name: a backtracking regex needs
    // about 100 ms per path here; the segment matcher needs microseconds.
    const m = globs("**/*a*a*a.b");
    const path = Array.from({ length: 16 }, () => "a".repeat(250)).join("/");
    const started = performance.now();
    for (let i = 0; i < 200; i++) expect(m[0]?.test(`${path}${i}`)).toBe(false);
    expect(performance.now() - started).toBeLessThan(1000);
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

describe("discoverFiles hardening", () => {
  it("never follows symlinks and skips oversized files", async () => {
    const { symlinkSync } = await import("node:fs");
    const dir = mkdtempSync(join(tmpdir(), "auditai-disc-"));
    mkdirSync(join(dir, "app"), { recursive: true });
    writeFileSync(join(dir, "app/route.ts"), "export const GET = () => new Response('ok');");
    symlinkSync("/etc/hosts", join(dir, "app/evil.ts"));
    symlinkSync("/etc", join(dir, "linked-dir"));
    writeFileSync(join(dir, "app/huge.ts"), "x".repeat(2 * 1024 * 1024 + 1));
    expect(discoverFiles(dir).source).toEqual(["app/route.ts"]);
  });
});

describe("hostile ignore globs (untrusted audit.config.json)", () => {
  it("walks a deep tree with a repeated-globstar glob in bounded time", () => {
    const dir = mkdtempSync(join(tmpdir(), "auditai-disc-"));
    const deep = join(dir, ...Array.from({ length: 21 }, () => "a"));
    mkdirSync(deep, { recursive: true });
    writeFileSync(join(deep, "route.ts"), "export const GET = () => new Response('ok');");
    // Ten `**/` used to compile to ten nested `(?:.*/)?` groups: seconds per path of backtracking.
    const hostile = `${"**/".repeat(10)}x`;
    const started = performance.now();
    const found = discoverFiles(dir, [], [hostile]);
    expect(performance.now() - started).toBeLessThan(500);
    expect(found.source).toEqual([`${"a/".repeat(21)}route.ts`]);
  });
});
