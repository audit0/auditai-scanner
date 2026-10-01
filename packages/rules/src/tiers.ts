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
  /**
   * A rule-targeted blind sample (repositories picked by the shapes the rule needs, only its findings
   * labelled): precision on unseen code, kept apart from `measured` because such a corpus is richer in
   * the rule's shapes than an average project and must not move the tier totals the product quotes.
   */
  targeted?: { real: number; falsePositive: number; unsure: number; sample: string };
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
    why: "a write policy for anon or PUBLIC decides with a tautology; an UPDATE or DELETE one on a table the same roles cannot read changes nothing through the Data API, and the rule makes that finding a lead itself",
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
  "supabase.dynamic-sql-from-function-parameter": {
    tier: "lead",
    measured: null,
    targeted: {
      real: 5,
      falsePositive: 2,
      unsure: 1,
      sample: "docs/realworld/2026-09-27-blind-sample-6-rules.md",
    },
    why: "SQL text read off the function body; on 26 September 2026 it found one function across the six corpora (155 repositories), a real injection read by hand, which is too few to claim more After the targeted blind sample, the two false-positive shapes it found (a parameter that only picks a literal CASE branch, an admin-only SQL runner) are silenced: 0 real lost on either corpus.",
  },
  "supabase.role-from-signup-metadata": {
    tier: "lead",
    measured: null,
    targeted: {
      real: 7,
      falsePositive: 0,
      unsure: 4,
      sample: "docs/realworld/2026-09-27-blind-sample-6-rules.md",
    },
    why: "read on 26 September 2026 across 155 repositories of six corpora: 12 findings in 11 repositories, 8 real (every repository a hand count found), 4 unsure (the sign-up function only in loose SQL outside the ordered migrations), no false positive. The tenant-column copy added 27 September: 3 findings, 2 real (salon_id, organisation_id), 1 unsure (loose SQL), no false positive. Not yet a blind sample, so it stays a lead",
  },
  "supabase.self-assignable-role-column": {
    tier: "lead",
    measured: null,
    targeted: {
      real: 21,
      falsePositive: 4,
      unsure: 9,
      sample: "docs/realworld/2026-09-27-blind-sample-6-rules.md",
    },
    why: "read on 26 September 2026 across 155 repositories of six corpora: 34 findings, 26 real, 2 false positive (a CHECK that allows no admin value, a policy dropped by a pg_policies loop), 6 unsure (loose SQL outside the ordered migrations, a Clerk-only app); not yet a blind sample, so it stays a lead After the targeted blind sample, rows no one creates and projects without a Supabase dependency are skipped: its 4 false positives (and closr, whose sign-up function a migration drops) go, 0 real lost; on the 155 repositories one finding goes (solistech-pro moved to Prisma and Auth.js).",
  },
  "supabase.self-writable-entitlement-column": {
    tier: "lead",
    measured: null,
    why: "read on 27 September 2026 across the cached corpora (about 700 repositories): 12 findings in 10 repositories, all correct as far as the code shows; 8 are credits, a balance, a plan or a KYC status the server trusts, 4 are game points or class coins (reported at medium). Built on repositories that were already read, so it stays a lead until a blind sample",
  },
  "supabase.view-runs-with-owner-rights": {
    tier: "lead",
    measured: null,
    why: "the view's reloptions and grants are facts, but a view is often meant to publish a subset of a protected table; unmeasured on 26 September 2026",
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
 *
 * A headline rule may mark one of its findings a lead itself, when the fact it reads holds but does
 * not reach anything today (an open UPDATE policy on a table nobody may read). That only ever lowers
 * the claim: no finding is raised above its rule's tier.
 */
export function applyTiers(findings: readonly Finding[]): Finding[] {
  return findings.map((f) => {
    const tier = f.tier === "lead" ? "lead" : tierOf(f.ruleId);
    if (tier === "headline") return { ...f, tier };
    if (RANK[f.severity] <= RANK[LEAD_SEVERITY_CAP]) return { ...f, tier };
    return { ...f, tier, severity: LEAD_SEVERITY_CAP, ruleSeverity: f.severity };
  });
}
