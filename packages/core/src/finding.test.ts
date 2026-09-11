import { describe, expect, it } from "vitest";
import {
  canTransition,
  DEFAULT_BLOCKING_POLICY,
  type Finding,
  IllegalTransitionError,
  isBlocking,
  isVerificationPassing,
  transition,
} from "./finding.js";

const base: Finding = {
  id: "AUDIT-1",
  ruleId: "supabase.cross-tenant-select",
  title: "Cross-tenant invoice read",
  status: "candidate",
  severity: "critical",
  confidence: 0.9,
  entrypoints: ["GET /api/invoices/[id]"],
  sources: ["route.param:id"],
  sinks: ["supabase.select(invoices)"],
  path: ["route param id", "service-role client", "invoices.select"],
  evidence: [],
  createdAt: "2026-09-11T00:00:00Z",
  updatedAt: "2026-09-11T00:00:00Z",
};

describe("transitions", () => {
  it("allows the happy path candidate -> likely -> confirmed -> fix_proposed -> fix_applied -> verified", () => {
    const ev = { kind: "llm" as const, summary: "trace" };
    let f = transition(base, "likely", { now: "t1" });
    f = transition(f, "confirmed", { evidence: ev, now: "t2" });
    f = transition(f, "fix_proposed", { now: "t3" });
    f = transition(f, "fix_applied", { now: "t4" });
    f = {
      ...f,
      verification: {
        securityTestBefore: "failed",
        securityTestAfter: "passed",
        existingTests: "passed",
        rescan: "passed",
        startedAt: "t4",
        finishedAt: "t5",
      },
    };
    f = transition(f, "verified", { evidence: { kind: "runtime", summary: "200 -> 403" } });
    expect(f.status).toBe("verified");
    expect(f.evidence).toHaveLength(2);
  });

  it("rejects illegal transitions", () => {
    expect(canTransition("candidate", "verified")).toBe(false);
    expect(() => transition(base, "verified")).toThrow(IllegalTransitionError);
    expect(canTransition("suppressed", "candidate")).toBe(false);
  });

  it("does not turn likely into confirmed without evidence", () => {
    const likely = transition(base, "likely");
    expect(() => transition(likely, "confirmed")).toThrow(/requires evidence/);
  });

  it("does not mark verified when verification is not passing", () => {
    const applied: Finding = {
      ...base,
      status: "fix_applied",
      verification: {
        securityTestBefore: "failed",
        securityTestAfter: "passed",
        existingTests: "failed",
        rescan: "passed",
        startedAt: "a",
        finishedAt: "b",
      },
    };
    expect(isVerificationPassing(applied.verification)).toBe(false);
    expect(() =>
      transition(applied, "verified", { evidence: { kind: "runtime", summary: "x" } }),
    ).toThrow(/passing verification/);
  });
});

describe("blocking policy", () => {
  it("never blocks unverified or low-confidence findings", () => {
    expect(isBlocking({ ...base, status: "unverified" })).toBe(false);
    expect(isBlocking({ ...base, status: "confirmed", confidence: 0.5 })).toBe(false);
    expect(isBlocking({ ...base, status: "candidate" })).toBe(false);
  });

  it("blocks confirmed high/critical and any verified finding", () => {
    expect(isBlocking({ ...base, status: "confirmed" })).toBe(true);
    expect(isBlocking({ ...base, status: "confirmed", severity: "medium" })).toBe(false);
    expect(isBlocking({ ...base, status: "verified", confidence: 0.1 })).toBe(true);
  });

  it("blocks a deterministic critical rule hit before LLM confirmation", () => {
    const det: Finding = {
      ...base,
      status: "likely",
      confidence: 1,
      evidence: [
        {
          kind: "rule",
          summary: "service_role key in client bundle",
          data: { deterministic: true },
        },
      ],
    };
    expect(isBlocking(det)).toBe(true);
    expect(isBlocking(det, { ...DEFAULT_BLOCKING_POLICY, blockDeterministicCritical: false })).toBe(
      false,
    );
  });

  it("never blocks suppressed findings", () => {
    expect(isBlocking({ ...base, status: "suppressed", confidence: 1 })).toBe(false);
  });
});
