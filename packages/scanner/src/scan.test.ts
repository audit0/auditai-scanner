import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { formatScanText } from "./format.js";
import { runScan, summarize } from "./scan.js";

const fixture = (variant: "vulnerable" | "secure"): string =>
  fileURLToPath(
    new URL(`../../../evals/fixtures/001-cross-tenant-invoice-read/${variant}/`, import.meta.url),
  );

describe("audit scan", () => {
  it("reports the cross-tenant read on the vulnerable fixture without blocking", () => {
    const r = runScan(fixture("vulnerable"), {
      now: "2026-09-11T00:00:00Z",
      sqlDirs: ["../supabase"],
    });
    expect(r.summary).toMatchObject({
      routes: 1,
      queries: 1,
      tablesKnown: 3,
      tablesWithRls: 3,
      rules: 11,
    });
    expect(r.findings.map((f) => f.status)).toEqual(["likely"]);
    expect(r.blocking).toBe(false);
    const text = formatScanText(r);
    expect(text).toContain(
      'AUDIT-001  LIKELY  CRITICAL  Cross-tenant select on "invoices" via service-role client',
    );
    expect(text).toContain("Entry   GET /api/invoices/[id]   app/api/invoices/[id]/route.ts:");
    expect(text).toContain(
      "Checked 1 risk in class authorization/RLS. Verified: 0. Confirmed (no sandbox): 0. Unverified: 0.",
    );
    expect(text).toContain("No blocking findings.");
  });

  it("reports nothing on the secure fixture", () => {
    const r = runScan(fixture("secure"), { sqlDirs: ["../supabase"] });
    expect(r.findings).toEqual([]);
    expect(formatScanText(r)).toContain("No findings. 1 route and 2 queries checked.");
  });

  it("counts RLS coverage over public tables only (storage.objects is Supabase-managed)", () => {
    const table = (name: string, rlsEnabled: boolean) => ({
      table: name,
      rlsEnabled,
      policies: [],
      policyDetails: [],
      columns: [],
      location: { file: "m.sql", line: 1 },
    });
    const s = summarize(
      {
        root: "/x",
        files: [],
        routes: [],
        clientFactories: [],
        authHelpers: [],
        tables: [table("invoices", true), table("notes", false), table("storage.objects", false)],
        exposures: [],
        fileIgnores: {},
        warnings: [],
      },
      8,
    );
    expect([s.tablesWithRls, s.tablesKnown]).toEqual([1, 2]);
  });
});
