import { type Finding, type Severity, transition } from "@auditai/core";
import type { SecurityGraph } from "@auditai/graph";
import type { ProjectModel } from "@auditai/parser";

export interface RuleContext {
  model: ProjectModel;
  graph: SecurityGraph;
  now: string;
  nextId: () => string;
}

/**
 * A deterministic rule. Rules never block on their own unless their evidence is marked deterministic;
 * they produce candidate/likely findings for the reasoning and verification stages.
 */
export interface Rule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: number;
  cwe: string[];
  evaluate(ctx: RuleContext): Finding[];
}

export interface RunOptions {
  now?: string;
  idPrefix?: string;
}

export function runRules(
  rules: readonly Rule[],
  model: ProjectModel,
  graph: SecurityGraph,
  opts: RunOptions = {},
): Finding[] {
  const now = opts.now ?? new Date().toISOString();
  const prefix = opts.idPrefix ?? "AUDIT";
  let counter = 0;
  const nextId = (): string => {
    counter += 1;
    return `${prefix}-${String(counter).padStart(3, "0")}`;
  };
  let findings: Finding[] = [];
  for (const rule of rules) {
    try {
      findings.push(...rule.evaluate({ model, graph, now, nextId }));
    } catch (e) {
      // A broken rule must never take the whole scan down; surface it as a model warning instead.
      model.warnings.push(`rule ${rule.id} failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  findings = applySuppressions(findings, model, now);
  return findings;
}

/**
 * Honors `auditai:ignore` directives: a directive above a handler suppresses findings whose entry is that
 * handler; a directive at the top of a file suppresses findings located in that file. Suppressed findings
 * stay in the output (with the reason) so reviewers can see what was silenced.
 */
export function applySuppressions(
  findings: Finding[],
  model: ProjectModel,
  now: string,
): Finding[] {
  const byEntry = new Map(model.routes.map((h) => [h.entry, h.ignores]));
  return findings.map((f) => {
    if (f.status === "suppressed") return f;
    const candidates = [...(byEntry.get(f.entrypoints[0] ?? "") ?? [])];
    for (const ev of f.evidence)
      for (const l of ev.locations ?? []) candidates.push(...(model.fileIgnores[l.file] ?? []));
    const hit = candidates.find((d) => d.ruleId === "*" || d.ruleId === f.ruleId);
    if (!hit) return f;
    return transition(f, "suppressed", {
      evidence: {
        kind: "rule",
        summary: `Suppressed by auditai:ignore at ${hit.location.file}:${hit.location.line}: ${hit.reason}`,
        locations: [hit.location],
        data: { suppressed: true, ruleId: hit.ruleId },
      },
      now,
    });
  });
}
