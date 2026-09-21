import type { Finding, FindingTier, Severity } from "@auditai/core";

/**
 * ADR-005 (accepted 21 September 2026): which rules may make a headline claim and which only point at
 * a place to look. Decided by measurement, not by taste — the numbers are real / false positive over
 * the 400 labelled findings of the four blind samples (docs/realworld/2026-09-20-schema-truth.md).
 *
 * Every rule of `defaultRules` must appear here; a test enforces it, so a new rule cannot ship without
 * someone deciding what the product may say about it.
 */
export interface RuleTier {
  tier: FindingTier;
  /** Measured on the blind samples: real / false positive. Null for a rule no sample reached. */
  measured: { real: number; falsePositive: number } | null;
  why: string;
}

export const RULE_TIERS: Readonly<Record<string, RuleTier>> = {
  // Facts about the database: a policy, a grant or the RLS switch, read as the database holds them.
  "supabase.rls-policy-trusts-user-metadata": {
    tier: "headline",
    measured: { real: 7, falsePositive: 0 },
    why: "the policy text itself decides on a claim the user writes",
  },
  "supabase.policies-without-rls-enabled": {
    tier: "headline",
    measured: { real: 2, falsePositive: 0 },
    why: "the RLS switch is off, so the policies are inert",
  },
  "supabase.table-without-rls": {
    tier: "headline",
    measured: { real: 4, falsePositive: 1 },
    why: "the RLS switch is off on an exposed table",
  },
  "supabase.anon-write-policy": {
    tier: "headline",
    measured: { real: 19, falsePositive: 11 },
    why: "a write policy for anon or PUBLIC decides with a tautology",
  },
  "supabase.security-definer-function-without-caller-check": {
    tier: "headline",
    measured: { real: 46, falsePositive: 51 },
    why: "a SECURITY DEFINER function anon or authenticated may execute, and the grant is a fact; a live snapshot removes the functions whose EXECUTE was revoked",
  },
  // The one code-layer exception: not an inference about reachability but the key itself, shipped to
  // the browser. It gives the whole database to anyone who opens the page.
  "supabase.service-role-key-exposed-to-client": {
    tier: "headline",
    measured: null,
    why: "the service-role key is in the browser bundle; nothing has to be inferred",
  },

  // Inferences: what reaches what through application code, or a database rule too weak on real code.
  "supabase.rls-policy-without-caller-predicate": {
    tier: "lead",
    measured: { real: 5, falsePositive: 6 },
    why: "a predicate without the caller is often a deliberately shared table",
  },
  "supabase.storage-policy-without-owner-check": {
    tier: "lead",
    measured: { real: 6, falsePositive: 6 },
    why: "a bucket-wide policy is often a deliberately shared bucket",
  },
  "supabase.service-role-object-access-without-tenant-scope": {
    tier: "lead",
    measured: { real: 30, falsePositive: 102 },
    why: "gates in middleware, helpers and parent records are routinely missed",
  },
  "supabase.service-role-query-without-authentication": {
    tier: "lead",
    measured: { real: 8, falsePositive: 38 },
    why: "authentication the parser does not recognise is common",
  },
  "supabase.mass-assignment-from-request-body": {
    tier: "lead",
    measured: { real: 6, falsePositive: 23 },
    why: "RLS WITH CHECK and allow-lists often make the extra columns harmless",
  },
  "supabase.user-controlled-tenant-scope": {
    tier: "lead",
    measured: { real: 4, falsePositive: 2 },
    why: "a membership check before the query is not always visible",
  },
  "supabase.role-check-from-user-metadata": {
    tier: "lead",
    measured: { real: 3, falsePositive: 1 },
    why: "code-level reading of a user-writable claim; too few samples to stand alone",
  },
  "supabase.server-trusts-unverified-session": {
    tier: "lead",
    measured: null,
    why: "code-level inference, not yet measured on a blind sample",
  },
  "supabase.storage-object-access-without-owner-scope": {
    tier: "lead",
    measured: { real: 0, falsePositive: 9 },
    why: "0 of 9 on four blind samples, because the parser marks server-built paths (a randomUUID, a database row, a verified context) as request input; still a lead rather than off, because the shape it looks for is a real hole and fixture 015 is one",
  },
};

const RANK: Readonly<Record<Severity, number>> = { low: 0, medium: 1, high: 2, critical: 3 };

/** A lead never claims more than this. Below `high`, it also leaves the blocking tier by definition. */
export const LEAD_SEVERITY_CAP: Severity = "medium";

export function tierOf(ruleId: string): FindingTier {
  return RULE_TIERS[ruleId]?.tier ?? "lead";
}

/**
 * What the product says about each finding. A rule the table does not know is treated as a lead:
 * an unmeasured claim is the weaker one. The rule's own severity is kept on a capped lead, so nothing
 * it said is lost — only what the product asserts changes.
 */
export function applyTiers(findings: readonly Finding[]): Finding[] {
  return findings.map((f) => {
    const tier = tierOf(f.ruleId);
    if (tier === "headline") return { ...f, tier };
    if (RANK[f.severity] <= RANK[LEAD_SEVERITY_CAP]) return { ...f, tier };
    return { ...f, tier, severity: LEAD_SEVERITY_CAP, ruleSeverity: f.severity };
  });
}
