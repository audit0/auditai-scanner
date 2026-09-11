import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  type CoverageSummary,
  type Finding,
  isBlocking,
  renderCoverageStatement,
  summarizeCoverage,
} from "@auditai/core";
import { buildGraph } from "@auditai/graph";
import { type ProjectModel, parseProject } from "@auditai/parser";
import { defaultRules, runRules } from "@auditai/rules";

export interface ScanOptions {
  now?: string;
  /** Extra directories with migration SQL, absolute or relative to the scanned path. */
  sqlDirs?: readonly string[];
  /** Glob patterns to leave out of the scan; merged with `audit.config.json` in the project. */
  ignore?: readonly string[];
}

/** Optional per-project settings, read from `<project>/audit.config.json`. */
export interface AuditConfig {
  ignore?: string[];
  migrations?: string[];
}

export function readAuditConfig(root: string): AuditConfig {
  const p = join(root, "audit.config.json");
  if (!existsSync(p)) return {};
  try {
    const raw = JSON.parse(readFileSync(p, "utf8")) as AuditConfig;
    return {
      ...(Array.isArray(raw.ignore)
        ? { ignore: raw.ignore.filter((x): x is string => typeof x === "string") }
        : {}),
      ...(Array.isArray(raw.migrations)
        ? { migrations: raw.migrations.filter((x): x is string => typeof x === "string") }
        : {}),
    };
  } catch {
    return {};
  }
}

export interface ScanSummary {
  root: string;
  files: number;
  routes: number;
  queries: number;
  tablesKnown: number;
  tablesWithRls: number;
  rules: number;
  warnings: string[];
}

export interface ScanResult {
  summary: ScanSummary;
  findings: Finding[];
  coverage: CoverageSummary;
  coverageStatement: string;
  blocking: boolean;
}

export function summarize(model: ProjectModel, rules: number): ScanSummary {
  return {
    root: model.root,
    files: model.files.length,
    routes: model.routes.length,
    queries: model.routes.reduce((n, r) => n + r.queries.length, 0),
    tablesKnown: model.tables.length,
    tablesWithRls: model.tables.filter((t) => t.rlsEnabled).length,
    rules,
    warnings: model.warnings,
  };
}

/** Deterministic pipeline: parse -> graph -> rules -> coverage. No model calls, no network. */
export function runScan(path: string, opts: ScanOptions = {}): ScanResult {
  const cfg = readAuditConfig(path);
  const sqlDirs = [...(cfg.migrations ?? []), ...(opts.sqlDirs ?? [])];
  const ignore = [...(cfg.ignore ?? []), ...(opts.ignore ?? [])];
  const model = parseProject(path, {
    ...(sqlDirs.length > 0 ? { sqlDirs } : {}),
    ...(ignore.length > 0 ? { ignore } : {}),
  });
  const graph = buildGraph(model);
  const runOpts = opts.now === undefined ? {} : { now: opts.now };
  const findings = runRules(defaultRules, model, graph, runOpts);
  const coverage = summarizeCoverage(findings);
  return {
    summary: summarize(model, defaultRules.length),
    findings,
    coverage,
    coverageStatement: renderCoverageStatement(coverage),
    blocking: findings.some((f) => isBlocking(f)),
  };
}
