import type { Finding, FindingStatus } from "@auditai/core";
import { isLead } from "./format.js";

/** How far a status has gone; below zero never fails a build. */
export const STATUS_RANK: Record<FindingStatus, number> = {
  suppressed: -1,
  unverified: -1,
  candidate: 0,
  likely: 1,
  confirmed: 2,
  fix_proposed: 2,
  fix_applied: 2,
  verified: 3,
};

/**
 * Whether `--fail-on <status>` stops the build. A lead never does (ADR-005): it is an inference from
 * application code that is right about one time in four, so a CI gate on `likely` would otherwise
 * fail on guesses.
 */
export function reachesFailOn(findings: readonly Finding[], failOn: FindingStatus): boolean {
  const threshold = STATUS_RANK[failOn];
  return findings.some(
    (f) => !isLead(f) && STATUS_RANK[f.status] >= 0 && STATUS_RANK[f.status] >= threshold,
  );
}
