import {
  type CoverageSummary,
  type Finding,
  isBlocking,
  renderCoverageStatement,
  summarizeCoverage,
} from "@auditai/core";
import { buildGraph } from "@auditai/graph";
import { checkIgnoreGlobs, type ProjectModel, parseProject } from "@auditai/parser";
import { defaultRules, runRules } from "@auditai/rules";
import { loadAuditConfig, repoMigrationDirs } from "./config.js";

export { type AuditConfig, readAuditConfig } from "./config.js";

export interface ScanOptions {
  now?: string;
  /**
   * Extra directories with migration SQL, absolute or relative to the scanned path. Trusted as given
   * (CLI flags, API options); `migrations` from the repository's own audit.config.json must stay
   * inside the project.
   */
  sqlDirs?: readonly string[];
  /** Glob patterns to leave out of the scan; merged with `audit.config.json` in the project. */
  ignore?: readonly string[];
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
  // RLS coverage counts the Data API tables only: keys of other schemas are qualified
  // (`storage.objects`) and their RLS is managed by Supabase, not by the project's migrations.
  const apiTables = model.tables.filter((t) => !t.table.includes("."));
  return {
    root: model.root,
    files: model.files.length,
    routes: model.routes.length,
    queries: model.routes.reduce((n, r) => n + r.queries.length, 0),
    tablesKnown: apiTables.length,
    tablesWithRls: apiTables.filter((t) => t.rlsEnabled).length,
    rules,
    warnings: model.warnings,
  };
}

/** Deterministic pipeline: parse -> graph -> rules -> coverage. No model calls, no network. */
export function runScan(path: string, opts: ScanOptions = {}): ScanResult {
  const cfg = loadAuditConfig(path);
  // The repository names its own migration folders, but only inside itself; the caller's are trusted.
  const repoDirs = repoMigrationDirs(path, cfg.config.migrations ?? []);
  const sqlDirs = [...repoDirs.dirs, ...(opts.sqlDirs ?? [])];
  const ignore = checkIgnoreGlobs([...(cfg.config.ignore ?? []), ...(opts.ignore ?? [])]);
  const model = parseProject(path, {
    ...(sqlDirs.length > 0 ? { sqlDirs } : {}),
    ...(ignore.globs.length > 0 ? { ignore: ignore.globs } : {}),
  });
  const graph = buildGraph(model);
  const runOpts = opts.now === undefined ? {} : { now: opts.now };
  const findings = runRules(defaultRules, model, graph, runOpts);
  const coverage = summarizeCoverage(findings);
  const summary = summarize(model, defaultRules.length);
  return {
    summary: {
      ...summary,
      // The parser repeats discovery warnings in the model; report each one once.
      warnings: [
        ...new Set([
          ...cfg.warnings,
          ...repoDirs.warnings,
          ...ignore.warnings,
          ...summary.warnings,
        ]),
      ],
    },
    findings,
    coverage,
    coverageStatement: renderCoverageStatement(coverage),
    blocking: findings.some((f) => isBlocking(f)),
  };
}
