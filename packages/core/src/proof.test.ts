import { describe, expect, it } from "vitest";
import { renderCoverageStatement, summarizeCoverage } from "./coverage.js";
import type { Finding } from "./finding.js";
import { buildProof, renderProofMarkdown } from "./proof.js";

const finding: Finding = {
  id: "AUDIT-173",
  ruleId: "supabase.cross-tenant-select",
  title: "Cross-tenant data access",
  status: "fix_applied",
  severity: "critical",
  confidence: 0.95,
  entrypoints: ["GET /api/projects/:projectId"],
  sources: [],
  sinks: [],
  path: [],
  evidence: [],
  verification: {
    securityTestBefore: "failed",
    securityTestAfter: "passed",
    existingTests: "passed",
    rescan: "passed",
    observedBefore: "HTTP 200",
    observedAfter: "HTTP 403",
    startedAt: "a",
    finishedAt: "b",
  },
  createdAt: "c",
  updatedAt: "d",
};

describe("proof", () => {
  it("renders a verified proof with before/after evidence", () => {
    const p = buildProof(finding, {
      expected: "Tenant A cannot access Tenant B",
      now: "2026-09-11T00:00:00Z",
    });
    expect(p.verdict).toBe("VERIFIED_FIX");
    const md = renderProofMarkdown(p);
    expect(md).toContain("FAIL (HTTP 200)");
    expect(md).toContain("PASS (HTTP 403)");
    expect(md).toContain("**Verdict: VERIFIED FIX**");
  });

  it("never fabricates PASS when verification did not run", () => {
    const { verification: _v, ...noVerification } = finding;
    const p = buildProof({ ...noVerification, status: "confirmed" }, { expected: "x" });
    expect(p.verdict).toBe("NOT_VERIFIED");
    expect(renderProofMarkdown(p)).toContain("SKIPPED");
  });
});

describe("coverage statement", () => {
  it("counts statuses and renders the honest statement", () => {
    const s = summarizeCoverage([
      finding,
      { ...finding, id: "2", status: "verified" },
      { ...finding, id: "3", status: "unverified" },
      { ...finding, id: "4", status: "suppressed" },
    ]);
    expect(s).toEqual({
      checked: 4,
      verified: 1,
      confirmed: 1,
      unverified: 1,
      candidates: 0,
      suppressed: 1,
    });
    expect(renderCoverageStatement(s)).toBe(
      "Checked 4 risks in class authorization/RLS. Verified: 1. Confirmed (no sandbox): 1. Unverified: 1.",
    );
  });
});
