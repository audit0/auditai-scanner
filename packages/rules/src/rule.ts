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
  /**
   * Tables the repository declares public in audit.config.json (ADR-002). Read-only findings of
   * `service-role-query-without-authentication` and `rls-policy-without-caller-predicate` on them
   * become `suppressed` with the reason "declared public in audit.config.json"; write paths, rpc
   * and the object-access rules are never affected.
   */
  publicTables?: readonly string[];
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
  findings = applyPublicTables(findings, opts.publicTables ?? [], now);
  return findings;
}

const PUBLIC_TABLE_RULES = new Set([
  "supabase.service-role-query-without-authentication",
  "supabase.rls-policy-without-caller-predicate",
]);
const READ_SINK = /^supabase\.select:public\.(.+)$/;

/**
 * ADR-002: a finding whose every sink is a `select` on a table the repository declared public is
 * suppressed, with the declaration named in the evidence. A policy finding must also be a select
 * policy (a `for all` policy governs writes). Suppressed findings stay in the output, so the
 * declaration is always visible in the report.
 */
export function applyPublicTables(
  findings: Finding[],
  publicTables: readonly string[],
  now: string,
): Finding[] {
  if (publicTables.length === 0) return findings;
  const declared = new Set(publicTables.map((t) => t.toLowerCase()));
  return findings.map((f) => {
    if (f.status === "suppressed" || !PUBLIC_TABLE_RULES.has(f.ruleId)) return f;
    if (f.sinks.length === 0) return f;
    const tables: string[] = [];
    for (const sink of f.sinks) {
      const table = READ_SINK.exec(sink)?.[1];
      if (table === undefined || !declared.has(table.toLowerCase())) return f;
      if (!tables.includes(table)) tables.push(table);
    }
    const command = f.evidence[0]?.data?.command;
    if (f.ruleId === "supabase.rls-policy-without-caller-predicate" && command !== "select") {
      return f;
    }
    return transition(f, "suppressed", {
      evidence: {
        kind: "rule",
        summary: `Suppressed: declared public in audit.config.json (publicTables: ${tables.join(", ")}). Every query of this finding only reads ${tables.map((t) => `public.${t}`).join(", ")}; the declaration never covers insert, update, delete or rpc paths, nor the object-access and mass-assignment rules.`,
        data: { suppressed: true, ruleId: f.ruleId, publicTables: tables },
      },
      now,
    });
  });
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
