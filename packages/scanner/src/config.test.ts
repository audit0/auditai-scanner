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

describe("publicTables from the repository's own audit.config.json (ADR-002)", () => {
  it("lowercases, de-duplicates and drops anything that is not a table name, with a warning each", () => {
    const { root } = layout({
      publicTables: ["Products", "products", " categories ", "public.x", "", 42, "drop;"],
    });
    const { config, warnings } = loadAuditConfig(root);
    expect(config.publicTables).toEqual(["products", "categories"]);
    expect(warnings).toHaveLength(4);
    expect(warnings[0]).toContain("ignored publicTables entry");
  });

  it("ignores a non-array with a warning and caps the list", () => {
    expect(loadAuditConfig(layout({ publicTables: "products" }).root)).toMatchObject({
      config: {},
      warnings: ["audit.config.json: publicTables ignored (not an array of table names)"],
    });
    const many = Array.from({ length: 70 }, (_, i) => `t${i}`);
    const { config, warnings } = loadAuditConfig(layout({ publicTables: many }).root);
    expect(config.publicTables).toHaveLength(64);
    expect(warnings).toHaveLength(6);
  });

  it("reaches the scan: the declaration is echoed in the summary and its suppressions counted", () => {
    const { root } = layout({ publicTables: ["inside"] });
    const r = runScan(root);
    expect(r.summary.publicTables).toEqual(["inside"]);
    expect(r.summary.warnings.filter((w) => w.includes("publicTables"))).toEqual([]);
  });
});

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
