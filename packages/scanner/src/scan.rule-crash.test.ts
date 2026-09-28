import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { formatScanText } from "./format.js";
import { runScan } from "./scan.js";

/**
 * REVIEW.md #1: a rule that throws must never make the scan look clean. `runRules` (rule.ts)
 * already catches the throw so one broken rule cannot take the whole scan down, but before this
 * fix its only trace was a line in `warnings`, which `blocking` and the CLI exit code ignored.
 *
 * `defaultRules` is mocked here (this file only — the mock is scoped per test file, so it does not
 * change the rule count other scan tests assert on) to add a rule that always throws, standing in
 * for a real rule bug without depending on one actually existing.
 */
vi.mock("@auditai/rules", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@auditai/rules")>();
  const alwaysThrows = {
    id: "test.always-throws",
    title: "test rule that always throws",
    description: "test rule that always throws",
    severity: "low",
    confidence: 0.5,
    cwe: [],
    evaluate() {
      throw new Error("boom");
    },
  };
  return { ...actual, defaultRules: [...actual.defaultRules, alwaysThrows] };
});

const fixture = (variant: "vulnerable" | "secure"): string =>
  fileURLToPath(
    new URL(`../../../evals/fixtures/001-cross-tenant-invoice-read/${variant}/`, import.meta.url),
  );

describe("a scan when a rule crashes", () => {
  it("marks the result incomplete and keeps the findings the surviving rules found", () => {
    const r = runScan(fixture("vulnerable"), {
      now: "2026-09-11T00:00:00Z",
      sqlDirs: ["../supabase"],
    });
    expect(r.incomplete).toBe(true);
    expect(r.summary.warnings).toContain("rule test.always-throws failed: boom");
    // The lead from the fixture's own rules is still reported: the crash cost only its own rule.
    expect(r.findings).toHaveLength(1);
  });

  it("says so in the printed report, not only in the trailing warning line", () => {
    const r = runScan(fixture("secure"), { sqlDirs: ["../supabase"] });
    const text = formatScanText(r);
    expect(text).toContain(
      "INCOMPLETE SCAN: a rule crashed before finishing (see warning below). This report is missing findings, not clean.",
    );
    expect(text).toContain("warning: rule test.always-throws failed: boom");
  });

  it("stays incomplete even on a project with nothing else to report", () => {
    const r = runScan(fixture("secure"), { sqlDirs: ["../supabase"] });
    expect(r.findings).toEqual([]);
    expect(r.blocking).toBe(false);
    expect(r.incomplete).toBe(true);
  });
});
