/**
 * Core finding model. See docs/AUDIT-ENGINE.md.
 * Severity = impact if real. Confidence = likelihood the finding is real. They are never mixed.
 */

export type Severity = "low" | "medium" | "high" | "critical";

export type FindingStatus =
  | "candidate"
  | "likely"
  | "confirmed"
  | "unverified"
  | "fix_proposed"
  | "fix_applied"
  | "verified"
  | "suppressed";

export const FINDING_STATUSES: readonly FindingStatus[] = [
  "candidate",
  "likely",
  "confirmed",
  "unverified",
  "fix_proposed",
  "fix_applied",
  "verified",
  "suppressed",
] as const;

export interface CodeLocation {
  file: string;
  line: number;
  column?: number;
  endLine?: number;
}

export type EvidenceKind = "rule" | "trace" | "llm" | "runtime";

export interface Evidence {
  kind: EvidenceKind;
  summary: string;
  locations?: CodeLocation[];
  /** Free-form structured data. `deterministic: true` marks certain rule evidence. */
  data?: Record<string, unknown>;
}

export interface FixProposal {
  summary: string;
  /** Unified diff limited to the finding. Unrelated refactors are not allowed. */
  diff: string;
  touchedFiles: string[];
  rationale: string;
}

export type CheckOutcome = "passed" | "failed" | "error" | "skipped";

export interface VerificationResult {
  /** Security regression test run against the vulnerable version. Expected: "failed". */
  securityTestBefore: CheckOutcome;
  /** Same test after the patch. Expected: "passed". */
  securityTestAfter: CheckOutcome;
  /** Project's existing test suite after the patch. */
  existingTests: CheckOutcome;
  /** Deterministic re-scan after the patch: "passed" means the path is no longer reachable. */
  rescan: CheckOutcome;
  observedBefore?: string;
  observedAfter?: string;
  sandboxRunId?: string;
  startedAt: string;
  finishedAt: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  status: FindingStatus;
  severity: Severity;
  /** 0..1 */
  confidence: number;
  cwe?: string[];
  entrypoints: string[];
  sources: string[];
  sinks: string[];
  /** Ordered path from entry to sink, as human-readable steps. */
  path: string[];
  evidence: Evidence[];
  fix?: FixProposal;
  verification?: VerificationResult;
  createdAt: string;
  updatedAt: string;
}

/** Allowed status transitions. Anything not listed is illegal. */
export const TRANSITIONS: Readonly<Record<FindingStatus, readonly FindingStatus[]>> = {
  candidate: ["likely", "unverified", "suppressed"],
  likely: ["confirmed", "unverified", "suppressed"],
  confirmed: ["fix_proposed", "suppressed"],
  unverified: ["likely", "confirmed", "suppressed"],
  fix_proposed: ["fix_applied", "confirmed", "suppressed"],
  fix_applied: ["verified", "fix_proposed", "suppressed"],
  verified: ["suppressed"],
  suppressed: [],
};

export function canTransition(from: FindingStatus, to: FindingStatus): boolean {
  return TRANSITIONS[from].includes(to);
}

export class IllegalTransitionError extends Error {
  override readonly name = "IllegalTransitionError";
  constructor(
    readonly findingId: string,
    readonly from: FindingStatus,
    readonly to: FindingStatus,
  ) {
    super(`Finding ${findingId}: illegal transition ${from} -> ${to}`);
  }
}

/**
 * Returns a new finding in status `to`. Throws on illegal transitions.
 * `likely -> confirmed` and `* -> verified` require evidence, because status must follow proof.
 */
export function transition(
  finding: Finding,
  to: FindingStatus,
  opts: { evidence?: Evidence; now?: string } = {},
): Finding {
  if (!canTransition(finding.status, to)) {
    throw new IllegalTransitionError(finding.id, finding.status, to);
  }
  const requiresEvidence = to === "confirmed" || to === "verified";
  if (requiresEvidence && !opts.evidence) {
    throw new Error(`Finding ${finding.id}: transition to ${to} requires evidence`);
  }
  if (to === "verified" && !isVerificationPassing(finding.verification)) {
    throw new Error(`Finding ${finding.id}: cannot mark verified without a passing verification`);
  }
  const evidence = opts.evidence ? [...finding.evidence, opts.evidence] : finding.evidence;
  return {
    ...finding,
    status: to,
    evidence,
    updatedAt: opts.now ?? new Date().toISOString(),
  };
}

/** Definition of Verified Fix from CLAUDE.md: all four checks must hold. A project without a test suite counts as passing its (empty) suite. */
export function isVerificationPassing(v: VerificationResult | undefined): v is VerificationResult {
  return (
    v !== undefined &&
    v.securityTestBefore === "failed" &&
    v.securityTestAfter === "passed" &&
    (v.existingTests === "passed" || v.existingTests === "skipped") &&
    v.rescan === "passed"
  );
}

export function isDeterministic(finding: Finding): boolean {
  return finding.evidence.some((e) => e.kind === "rule" && e.data?.deterministic === true);
}

export interface BlockingPolicy {
  /** Findings below this confidence never block. */
  minConfidence: number;
  /** Confirmed (or further) findings of these severities block. */
  blockOnConfirmedSeverities: readonly Severity[];
  /** A deterministic critical rule hit blocks even before LLM confirmation. */
  blockDeterministicCritical: boolean;
}

export const DEFAULT_BLOCKING_POLICY: BlockingPolicy = {
  minConfidence: 0.8,
  blockOnConfirmedSeverities: ["high", "critical"],
  blockDeterministicCritical: true,
};

const CONFIRMED_OR_LATER: readonly FindingStatus[] = ["confirmed", "fix_proposed", "fix_applied"];

/**
 * Blocking policy from docs/AUDIT-ENGINE.md.
 * Never block on low confidence, unverified findings, or suppressed ones.
 */
export function isBlocking(
  finding: Finding,
  policy: BlockingPolicy = DEFAULT_BLOCKING_POLICY,
): boolean {
  if (finding.status === "suppressed") return false;
  if (finding.status === "verified") return true;
  if (finding.confidence < policy.minConfidence) return false;
  if (
    CONFIRMED_OR_LATER.includes(finding.status) &&
    policy.blockOnConfirmedSeverities.includes(finding.severity)
  ) {
    return true;
  }
  if (
    policy.blockDeterministicCritical &&
    finding.severity === "critical" &&
    isDeterministic(finding) &&
    finding.status !== "unverified"
  ) {
    return true;
  }
  return false;
}
