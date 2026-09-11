import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
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
  entrypoints: string[];
  mustMentionFiles: string[];
  mustNotFlag: string[];
}

const fixtures = readdirSync(FIXTURES).filter((d) =>
  existsSync(join(FIXTURES, d, "expected-finding.json")),
);

describe.each(fixtures)("fixture %s", (name) => {
  const expected = JSON.parse(
    readFileSync(join(FIXTURES, name, "expected-finding.json"), "utf8"),
  ) as Expected;

  it("vulnerable variant yields the expected finding", () => {
    const r = runScan(join(FIXTURES, name, "vulnerable"), {
      sqlDirs: [join(FIXTURES, name, "supabase")],
    });
    const hit = r.findings.find((f) => f.ruleId === expected.ruleId);
    expect(hit, `expected rule ${expected.ruleId} to fire`).toBeDefined();
    expect(hit?.severity).toBe(expected.severity);
    expect(hit?.confidence ?? 0).toBeGreaterThanOrEqual(expected.minConfidence);
    for (const entry of expected.entrypoints) expect(hit?.entrypoints).toContain(entry);
    const mentioned = new Set(hit?.evidence.flatMap((e) => e.locations?.map((l) => l.file) ?? []));
    for (const file of expected.mustMentionFiles) {
      expect([...mentioned], `must mention ${file}`).toContain(file.replace(/^vulnerable\//, ""));
    }
  });

  it("secure variant yields no finding for that rule", () => {
    const r = runScan(join(FIXTURES, name, "secure"), {
      sqlDirs: [join(FIXTURES, name, "supabase")],
    });
    expect(r.findings.filter((f) => f.ruleId === expected.ruleId)).toEqual([]);
    expect(r.blocking).toBe(false);
  });
});
