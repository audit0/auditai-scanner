import type { Finding } from "@auditai/core";
import { buildGraph } from "@auditai/graph";
import type { ProjectModel } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { type Rule, type RuleContext, runRules } from "./rule.js";

const emptyModel = (): ProjectModel => ({
  root: "/x",
  files: [],
  routes: [],
  clientFactories: [],
  authHelpers: [],
  tables: [],
  exposures: [],
  fileIgnores: {},
  warnings: [],
});

const finding = (ctx: RuleContext, ruleId: string): Finding => ({
  id: ctx.nextId(),
  ruleId,
  title: `finding from ${ruleId}`,
  status: "candidate",
  severity: "low",
  confidence: 0.5,
  entrypoints: [],
  sources: [],
  sinks: [],
  path: [],
  evidence: [],
  createdAt: ctx.now,
  updatedAt: ctx.now,
});

const rule = (id: string, evaluate: Rule["evaluate"]): Rule => ({
  id,
  title: id,
  description: id,
  severity: "low",
  confidence: 0.5,
  cwe: [],
  evaluate,
});

describe("runRules", () => {
  it("keeps findings from other rules when one rule throws, and records the failure as a warning", () => {
    const model = emptyModel();
    const graph = buildGraph(model);
    const good = rule("good.rule", (ctx) => [finding(ctx, "good.rule")]);
    const broken = rule("broken.rule", () => {
      throw new Error("unexpected graph shape");
    });
    const alsoGood = rule("also-good.rule", (ctx) => [finding(ctx, "also-good.rule")]);

    const findings = runRules([good, broken, alsoGood], model, graph, {
      now: "2026-09-28T00:00:00Z",
    });

    expect(findings.map((f) => f.ruleId)).toEqual(["good.rule", "also-good.rule"]);
    expect(model.warnings).toEqual(["rule broken.rule failed: unexpected graph shape"]);
  });

  it("does not lose non-Error throws", () => {
    const model = emptyModel();
    const graph = buildGraph(model);
    const broken = rule("broken.rule", () => {
      throw "not an Error instance";
    });

    runRules([broken], model, graph, { now: "2026-09-28T00:00:00Z" });

    expect(model.warnings).toEqual(["rule broken.rule failed: not an Error instance"]);
  });

  it("records one warning per failing rule, so a caller can tell a scan is incomplete", () => {
    const model = emptyModel();
    const graph = buildGraph(model);
    const brokenA = rule("broken.a", () => {
      throw new Error("a");
    });
    const brokenB = rule("broken.b", () => {
      throw new Error("b");
    });

    const warningsBefore = model.warnings.length;
    runRules([brokenA, brokenB], model, graph, { now: "2026-09-28T00:00:00Z" });

    // scan.ts and scan-snapshot.ts treat any growth of `model.warnings` across this call as proof
    // that a rule crashed (REVIEW.md #1): nothing else touches `model.warnings` here.
    expect(model.warnings.length - warningsBefore).toBe(2);
  });
});
