import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadAuditConfig, repoMigrationDirs } from "./config.js";
import { runScan } from "./scan.js";

/** A repository next to a directory it must not be able to reach: `<base>/repo` and `<base>/outside`. */
function layout(config: unknown | ((outside: string) => unknown)): {
  base: string;
  root: string;
  outside: string;
} {
  const base = mkdtempSync(join(tmpdir(), "auditai-cfg-"));
  const root = join(base, "repo");
  const outside = join(base, "outside");
  mkdirSync(join(root, "supabase/migrations"), { recursive: true });
  mkdirSync(outside, { recursive: true });
  writeFileSync(
    join(root, "supabase/migrations/0001_inside.sql"),
    "create table public.inside (id uuid primary key);\nalter table public.inside enable row level security;\n",
  );
  writeFileSync(
    join(outside, "leak.sql"),
    "create table public.leak (id uuid primary key);\nalter table public.leak enable row level security;\n",
  );
  symlinkSync("../outside", join(root, "db-link"));
  const value = typeof config === "function" ? config(outside) : config;
  writeFileSync(
    join(root, "audit.config.json"),
    typeof value === "string" ? value : JSON.stringify(value),
  );
  return { base, root, outside };
}

describe("migrations from the repository's own audit.config.json", () => {
  it("never reads SQL outside the project, through .., absolute paths or symlinks", () => {
    const { root } = layout((outside) => ({
      migrations: [
        "../outside",
        outside,
        "db-link",
        "supabase/../../outside",
        "supabase/migrations",
      ],
    }));
    const r = runScan(root);
    expect(r.summary.tablesKnown).toBe(1);
    const dropped = r.summary.warnings.filter((w) => w.includes("ignored migrations entry"));
    expect(dropped).toHaveLength(4);
    expect(dropped.join("\n")).toContain('"../outside"');
    expect(dropped.join("\n")).toContain('"db-link"');
  });

  it("still reads directories passed by the caller (CLI flags, API options)", () => {
    const { root, outside } = layout({ migrations: ["supabase/migrations"] });
    const r = runScan(root, { sqlDirs: [outside] });
    expect(r.summary.tablesKnown).toBe(2);
    expect(r.summary.warnings).toEqual([]);
  });

  it("drops host paths without touching the filesystem outside the root", () => {
    const { root } = layout({});
    const r = repoMigrationDirs(root, [
      "/",
      "../..",
      "/etc",
      "C:\\Windows",
      "..\\..\\etc",
      "a/../../b",
      "missing",
      "supabase/migrations/0001_inside.sql",
      "supabase/migrations",
      "./supabase/migrations/",
    ]);
    // The same directory twice is walked once.
    expect(r.dirs).toEqual(["supabase/migrations"]);
    expect(r.warnings).toHaveLength(8);
    for (const w of r.warnings)
      expect(w).toMatch(/^audit\.config\.json: ignored migrations entry /);
  });
});

describe("audit.config.json parsing", () => {
  it("reports a config that is not a JSON object instead of silently ignoring it", () => {
    for (const bad of ["{ not json", "null", "[1,2]", '"text"']) {
      const { root } = layout(bad);
      const loaded = loadAuditConfig(root);
      expect(loaded.config).toEqual({});
      expect(loaded.warnings, bad).toHaveLength(1);
      expect(loaded.warnings[0]).toMatch(/^audit\.config\.json ignored: /);
    }
  });

  it("surfaces rejected ignore globs in the scan summary", () => {
    const { root } = layout({ ignore: [`${"**/".repeat(10)}x`, "a/**/b/**/c", "evals/**"] });
    const r = runScan(root);
    expect(r.summary.warnings).toEqual([
      'ignore glob "a/**/b/**/c" rejected: more than 1 "**" segment',
    ]);
  });
});
