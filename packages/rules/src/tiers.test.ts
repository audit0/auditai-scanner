import type { Finding } from "@auditai/core";
import { isBlocking } from "@auditai/core";
import { describe, expect, it } from "vitest";
import { defaultRules } from "./index.js";
import { applyTiers, LEAD_SEVERITY_CAP, RULE_TIERS, tierOf } from "./tiers.js";

/** ADR-005 (accepted 21 September 2026): what the product may claim is decided per rule, by measurement. */

const finding = (
  ruleId: string,
  severity: Finding["severity"],
  over: Partial<Finding> = {},
): Finding => ({
  id: "AUDIT-001",
  ruleId,
  title: "t",
  status: "likely",
  severity,
  confidence: 0.9,
  entrypoints: [],
  sources: [],
  sinks: [],
  path: [],
  evidence: [{ kind: "rule", summary: "s", data: { deterministic: true } }],
  createdAt: "2026-09-21T00:00:00Z",
  updatedAt: "2026-09-21T00:00:00Z",
  ...over,
});

describe("rule tiers", () => {
  it("names every enabled rule, so no rule ships without a decision about what it may claim", () => {
    for (const r of defaultRules) expect(RULE_TIERS[r.id], r.id).toBeDefined();
  });

  it("gives a headline only to rules that read a fact, and records the measurement behind each", () => {
    const headline = Object.entries(RULE_TIERS)
      .filter(([, t]) => t.tier === "headline")
      .map(([id]) => id.replace("supabase.", ""))
      .sort();
    expect(headline).toEqual([
      "anon-write-policy",
      "policies-without-rls-enabled",
      "rls-policy-trusts-user-metadata",
      "security-definer-function-without-caller-check",
      "service-role-key-exposed-to-client",
      "table-without-rls",
    ]);
    // The totals the product quotes: headlines 55%, leads about one in four (25%).
    const sum = (tier: string) =>
      Object.values(RULE_TIERS)
        .filter((t) => t.tier === tier && t.measured)
        .reduce(
          (acc, t) => ({
            real: acc.real + (t.measured?.real ?? 0),
            fp: acc.fp + (t.measured?.falsePositive ?? 0),
          }),
          { real: 0, fp: 0 },
        );
    const h = sum("headline");
    const l = sum("lead");
    expect(Math.round((100 * h.real) / (h.real + h.fp))).toBe(55);
    expect(Math.round((100 * l.real) / (l.real + l.fp))).toBe(25);
  });

  it("caps a lead at medium, keeps what the rule said, and never lets it block", () => {
    const deterministicCritical = finding(
      "supabase.service-role-object-access-without-tenant-scope",
      "critical",
    );
    const [lead] = applyTiers([deterministicCritical]);
    expect(lead).toMatchObject({
      tier: "lead",
      severity: LEAD_SEVERITY_CAP,
      ruleSeverity: "critical",
    });
    expect(isBlocking(deterministicCritical)).toBe(true);
    expect(isBlocking(lead as Finding)).toBe(false);
    // Confirmed in a sandbox and still a lead: the tier, not the status, decides what the product claims.
    expect(isBlocking({ ...(lead as Finding), status: "verified" })).toBe(false);
    // A lead the rule already rated medium or lower is not touched beyond the tier.
    const [low] = applyTiers([finding("supabase.mass-assignment-from-request-body", "low")]);
    expect(low).toMatchObject({ tier: "lead", severity: "low" });
    expect(low?.ruleSeverity).toBeUndefined();
  });

  it("leaves a headline exactly as the rule rated it, and treats an unknown rule as a lead", () => {
    const [h] = applyTiers([finding("supabase.anon-write-policy", "critical")]);
    expect(h).toMatchObject({ tier: "headline", severity: "critical" });
    expect(h?.ruleSeverity).toBeUndefined();
    expect(isBlocking(h as Finding)).toBe(true);
    expect(tierOf("supabase.a-rule-nobody-measured")).toBe("lead");
  });

  it("keeps a lead that a headline rule marked itself, capped like any lead, and never raises one", () => {
    const [own] = applyTiers([{ ...finding("supabase.anon-write-policy", "high"), tier: "lead" }]);
    expect(own).toMatchObject({ tier: "lead", severity: LEAD_SEVERITY_CAP, ruleSeverity: "high" });
    expect(isBlocking(own as Finding)).toBe(false);
    const [raised] = applyTiers([
      { ...finding("supabase.mass-assignment-from-request-body", "high"), tier: "headline" },
    ]);
    expect(raised).toMatchObject({ tier: "lead", severity: LEAD_SEVERITY_CAP });
  });
});
