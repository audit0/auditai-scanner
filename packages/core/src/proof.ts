import type { CheckOutcome, Finding, VerificationResult } from "./finding.js";
import { isVerificationPassing } from "./finding.js";

/**
 * Verified Security Proof: the product object. See docs/VERIFICATION.md.
 * A proof is only "verified" when the full protocol passed; otherwise it says so.
 */
export interface Proof {
  findingId: string;
  title: string;
  severity: Finding["severity"];
  entry: string;
  expected: string;
  verdict: "VERIFIED_FIX" | "NOT_VERIFIED";
  before: { securityTest: CheckOutcome; observed?: string };
  after: {
    securityTest: CheckOutcome;
    existingTests: CheckOutcome;
    rescan: CheckOutcome;
    observed?: string;
  };
  generatedAt: string;
}

export function buildProof(finding: Finding, opts: { expected: string; now?: string }): Proof {
  const v: VerificationResult | undefined = finding.verification;
  const passing = isVerificationPassing(v);
  const before: Proof["before"] = { securityTest: v?.securityTestBefore ?? "skipped" };
  if (v?.observedBefore !== undefined) before.observed = v.observedBefore;
  const after: Proof["after"] = {
    securityTest: v?.securityTestAfter ?? "skipped",
    existingTests: v?.existingTests ?? "skipped",
    rescan: v?.rescan ?? "skipped",
  };
  if (v?.observedAfter !== undefined) after.observed = v.observedAfter;
  return {
    findingId: finding.id,
    title: finding.title,
    severity: finding.severity,
    entry: finding.entrypoints[0] ?? "(unknown entry)",
    expected: opts.expected,
    verdict: passing ? "VERIFIED_FIX" : "NOT_VERIFIED",
    before,
    after,
    generatedAt: opts.now ?? new Date().toISOString(),
  };
}

const MARK: Record<CheckOutcome, string> = {
  passed: "PASS",
  failed: "FAIL",
  error: "ERROR",
  skipped: "SKIPPED",
};

/** Plain-text proof block for PR comments, CLI output and reports. English only. */
export function renderProofMarkdown(p: Proof): string {
  const lines = [
    `### ${p.findingId}: ${p.title}`,
    "",
    `**Severity:** ${p.severity}`,
    `**Entry:** \`${p.entry}\``,
    `**Expected:** ${p.expected}`,
    "",
    "| Check | Result |",
    "|---|---|",
    `| Security test before patch | ${MARK[p.before.securityTest]}${p.before.observed ? ` (${p.before.observed})` : ""} |`,
    `| Security test after patch | ${MARK[p.after.securityTest]}${p.after.observed ? ` (${p.after.observed})` : ""} |`,
    `| Existing tests after patch | ${MARK[p.after.existingTests]} |`,
    `| Deterministic re-scan | ${MARK[p.after.rescan]} |`,
    "",
    p.verdict === "VERIFIED_FIX" ? "**Verdict: VERIFIED FIX**" : "**Verdict: NOT VERIFIED**",
  ];
  return `${lines.join("\n")}\n`;
}
