import { statSync } from "node:fs";
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
import { errorCode, loadAuditConfig, repoMigrationDirs } from "./config.js";

export { type AuditConfig, readAuditConfig } from "./config.js";

/** Why a scan could not start. `path_not_found`: the path is missing or is not a directory. */
export type ScanErrorCode = "path_not_found";

/** A scan that never started. `message` is one line, ready for stderr. */
export class ScanError extends Error {
  override readonly name = "ScanError";
  constructor(
    readonly code: ScanErrorCode,
    readonly path: string,
    message: string,
  ) {
    super(message);
  }
}

/**
 * The scanned path must be a directory. Walking a missing one would otherwise yield an empty model
 * and an honest-looking "No findings" summary for a project that was never looked at.
 */
function ensureDirectory(path: string): void {
  let isDirectory: boolean;
  try {
    isDirectory = statSync(path).isDirectory();
  } catch (e) {
    const code = errorCode(e);
    const why = code === "ENOENT" ? "no such file or directory" : code;
    throw new ScanError("path_not_found", path, `${path} is not a directory (${why})`);
  }
  if (!isDirectory) throw new ScanError("path_not_found", path, `${path} is not a directory`);
}

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
  /** Tables the repository's audit.config.json declares public (ADR-002); always shown in the report. */
  publicTables: string[];
}

export interface ScanResult {
  summary: ScanSummary;
  findings: Finding[];
  coverage: CoverageSummary;
  coverageStatement: string;
  blocking: boolean;
}

export function summarize(
  model: ProjectModel,
  rules: number,
  publicTables: readonly string[] = [],
): ScanSummary {
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
    publicTables: [...publicTables],
  };
}

/**
 * Deterministic pipeline: parse -> graph -> rules -> coverage. No model calls, no network.
 * Throws ScanError (`path_not_found`) when `path` is not a directory.
 */
export function runScan(path: string, opts: ScanOptions = {}): ScanResult {
  ensureDirectory(path);
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
  // The repository's own declaration of public tables: untrusted, validated in loadAuditConfig,
  // always echoed in the summary so a reviewer sees what it silenced.
  const publicTables = cfg.config.publicTables ?? [];
  const runOpts = { ...(opts.now === undefined ? {} : { now: opts.now }), publicTables };
  const findings = runRules(defaultRules, model, graph, runOpts);
  const coverage = summarizeCoverage(findings);
  const summary = summarize(model, defaultRules.length, publicTables);
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
