import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding } from "@auditai/core";
import { runScan } from "@auditai/scanner";
import { describe, expect, it } from "vitest";

/**
 * Eval gate: every fixture with an expected-finding.json must be caught on its vulnerable variant
 * and stay silent on its secure variant. Never edit expectations to make a rule pass; fix the rule.
 */
const FIXTURES = fileURLToPath(new URL("../fixtures/", import.meta.url));

interface Expected {
  ruleId: string;
  severity: string;
  minConfidence: number;
  /** Every entry point listed must be flagged by the rule (a fixture may hold several routes). */
  entrypoints: string[];
  mustMentionFiles: string[];
  mustNotFlag: string[];
  /**
   * When set, the secure variant still produces a finding of the rule, but suppressed with a reason
   * containing this text (a declaration in audit.config.json, shown in the report). Suppressed
   * findings never block and are the only ones the secure variant may carry.
   */
  secureSuppressedReason?: string;
}

const fixtures = readdirSync(FIXTURES).filter((d) =>
  existsSync(join(FIXTURES, d, "expected-finding.json")),
);

const reported = (f: Finding): boolean => f.status !== "suppressed";

describe.each(fixtures)("fixture %s", (name) => {
  const expected = JSON.parse(
    readFileSync(join(FIXTURES, name, "expected-finding.json"), "utf8"),
  ) as Expected;

  it("vulnerable variant yields the expected finding", () => {
    const r = runScan(join(FIXTURES, name, "vulnerable"), {
      sqlDirs: [join(FIXTURES, name, "supabase")],
    });
    const hits = r.findings.filter((f) => f.ruleId === expected.ruleId && reported(f));
    expect(hits.length, `expected rule ${expected.ruleId} to fire`).toBeGreaterThan(0);
    const strong = hits.filter(
      (h) => h.severity === expected.severity && h.confidence >= expected.minConfidence,
    );
    expect(
      strong.length,
      `expected a ${expected.severity} finding with confidence >= ${expected.minConfidence}`,
    ).toBeGreaterThan(0);
    for (const entry of expected.entrypoints) {
      expect(
        strong.some((h) => h.entrypoints.includes(entry)),
        `entry point ${entry} must be flagged`,
      ).toBe(true);
    }
    const mentioned = new Set(
      strong.flatMap((h) => h.evidence.flatMap((e) => e.locations?.map((l) => l.file) ?? [])),
    );
    for (const file of expected.mustMentionFiles) {
      expect([...mentioned], `must mention ${file}`).toContain(file.replace(/^vulnerable\//, ""));
    }
  });

  it("secure variant yields no finding for that rule", () => {
    const r = runScan(join(FIXTURES, name, "secure"), {
      sqlDirs: [join(FIXTURES, name, "supabase")],
    });
    const ofRule = r.findings.filter((f) => f.ruleId === expected.ruleId);
    expect(ofRule.filter(reported)).toEqual([]);
    expect(r.blocking).toBe(false);
    if (expected.secureSuppressedReason !== undefined) {
      const reason = expected.secureSuppressedReason;
      expect(
        ofRule.some((f) => f.evidence.some((e) => e.summary.includes(reason))),
        `secure variant must carry a suppressed finding mentioning "${reason}"`,
      ).toBe(true);
    } else {
      expect(ofRule).toEqual([]);
    }
  });
});

/**
 * Sandbox integrity: the verifier reads DENY titles as security assertions and ALLOW titles as sanity
 * checks. An unlabeled test counts as a security assertion, so a merely broken app could look like a
 * reproduced vulnerability. Every fixture test is labeled, and every file asserts at least one DENY.
 */
const TEST_TITLE = /^\s*(?:it|test)(?:\.\w+)?\(\s*(["'`])((?:\\.|(?!\1).)*)\1/gm;

describe.each(fixtures.filter((d) => existsSync(join(FIXTURES, d, "security-test"))))(
  "fixture %s security tests",
  (name) => {
    it("label every test DENY or ALLOW and assert at least one DENY", () => {
      const dir = join(FIXTURES, name, "security-test");
      const files = readdirSync(dir).filter((f) => f.endsWith(".test.ts"));
      expect(files.length).toBeGreaterThan(0);
      for (const file of files) {
        const titles = [...readFileSync(join(dir, file), "utf8").matchAll(TEST_TITLE)].map(
          (m) => m[2] ?? "",
        );
        expect(titles.length, file).toBeGreaterThan(0);
        expect(
          titles.filter((t) => !/\b(DENY|ALLOW)\b/.test(t)),
          `${file}: unlabeled tests`,
        ).toEqual([]);
        expect(
          titles.some((t) => /\bDENY\b/.test(t)),
          `${file}: no DENY test`,
        ).toBe(true);
      }
    });
  },
);
