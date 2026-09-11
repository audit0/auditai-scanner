import type { Finding } from "./finding.js";

/**
 * Honest coverage statement (docs/PRODUCT.md). The product never says "all holes are closed";
 * it says how many risks were checked and how many were verified, confirmed, or left unverified.
 */
export interface CoverageSummary {
  checked: number;
  verified: number;
  confirmed: number;
  unverified: number;
  candidates: number;
  suppressed: number;
}

export function summarizeCoverage(findings: readonly Finding[]): CoverageSummary {
  const s: CoverageSummary = {
    checked: findings.length,
    verified: 0,
    confirmed: 0,
    unverified: 0,
    candidates: 0,
    suppressed: 0,
  };
  for (const f of findings) {
    switch (f.status) {
      case "verified":
        s.verified += 1;
        break;
      case "confirmed":
      case "fix_proposed":
      case "fix_applied":
        s.confirmed += 1;
        break;
      case "unverified":
        s.unverified += 1;
        break;
      case "suppressed":
        s.suppressed += 1;
        break;
      case "candidate":
      case "likely":
        s.candidates += 1;
        break;
    }
  }
  return s;
}

export function renderCoverageStatement(
  s: CoverageSummary,
  riskClass = "authorization/RLS",
): string {
  return (
    `Checked ${s.checked} risk${s.checked === 1 ? "" : "s"} in class ${riskClass}. ` +
    `Verified: ${s.verified}. Confirmed (no sandbox): ${s.confirmed}. Unverified: ${s.unverified}.`
  );
}
