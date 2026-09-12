import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join, resolve, sep } from "node:path";

/** Optional per-project settings, read from `<project>/audit.config.json`. */
export interface AuditConfig {
  ignore?: string[];
  migrations?: string[];
  /**
   * Tables whose rows are public by design (a catalogue, a price list). Read-only findings of the
   * unauthenticated-query and policy rules on them are suppressed with the declaration named in
   * the report (ADR-002). Lowercase bare table names; write paths are never covered.
   */
  publicTables?: string[];
}

/** A declaration longer than this is a mistake, not a catalogue. */
const MAX_PUBLIC_TABLES = 64;
const TABLE_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

export interface LoadedAuditConfig {
  config: AuditConfig;
  /** Why the file, or part of it, was not used. */
  warnings: string[];
}

/**
 * Directories named by the repository config. More would only multiply walks of the same tree;
 * a real project keeps its migrations in one or two places.
 */
const MAX_REPO_MIGRATION_DIRS = 16;

function shown(value: string): string {
  return JSON.stringify(value.length > 120 ? `${value.slice(0, 120)}...` : value);
}

export function errorCode(e: unknown): string {
  if (e instanceof Error && "code" in e && typeof e.code === "string") return e.code;
  return e instanceof Error ? e.message : String(e);
}

const strings = (v: unknown): string[] | undefined =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : undefined;

/** Reads `<root>/audit.config.json`. The file belongs to the scanned repository: untrusted input. */
export function loadAuditConfig(root: string): LoadedAuditConfig {
  const p = join(root, "audit.config.json");
  if (!existsSync(p)) return { config: {}, warnings: [] };
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(p, "utf8"));
  } catch (e) {
    const why = e instanceof SyntaxError ? "not valid JSON" : `unreadable (${errorCode(e)})`;
    return { config: {}, warnings: [`audit.config.json ignored: ${why}`] };
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { config: {}, warnings: ["audit.config.json ignored: not a JSON object"] };
  }
  const obj = raw as Record<string, unknown>;
  const ignore = strings(obj.ignore);
  const migrations = strings(obj.migrations);
  const publicTables = publicTableNames(obj.publicTables);
  return {
    config: {
      ...(ignore ? { ignore } : {}),
      ...(migrations ? { migrations } : {}),
      ...(publicTables.tables ? { publicTables: publicTables.tables } : {}),
    },
    warnings: publicTables.warnings,
  };
}

/** Validated, lowercased, de-duplicated `publicTables`; anything that is not a bare table name is dropped with a warning. */
function publicTableNames(value: unknown): { tables?: string[]; warnings: string[] } {
  const warnings: string[] = [];
  if (value === undefined) return { warnings };
  if (!Array.isArray(value)) {
    return { warnings: ["audit.config.json: publicTables ignored (not an array of table names)"] };
  }
  const tables: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string" || !TABLE_NAME.test(entry.trim())) {
      warnings.push(
        `audit.config.json: ignored publicTables entry ${shown(String(entry))} (not a table name)`,
      );
      continue;
    }
    const name = entry.trim().toLowerCase();
    if (tables.includes(name)) continue;
    if (tables.length >= MAX_PUBLIC_TABLES) {
      warnings.push(
        `audit.config.json: ignored publicTables entry ${shown(entry)} (at most ${MAX_PUBLIC_TABLES} tables)`,
      );
      continue;
    }
    tables.push(name);
  }
  return { tables, warnings };
}

export function readAuditConfig(root: string): AuditConfig {
  return loadAuditConfig(root).config;
}

function inside(base: string, p: string): boolean {
  return p === base || p.startsWith(base.endsWith(sep) ? base : `${base}${sep}`);
}

/**
 * The `migrations` entries of the repository's own config that may be walked: relative paths to
 * directories that stay inside the project, after symlinks. Everything else (absolute paths, `..`,
 * a committed symlink to `/`) is dropped with a warning; a trusted caller passes such directories
 * through ScanOptions.sqlDirs instead. Only the filesystem inside `root` is looked at.
 */
export function repoMigrationDirs(
  root: string,
  entries: readonly string[],
): { dirs: string[]; warnings: string[] } {
  const dirs: string[] = [];
  const warnings: string[] = [];
  const drop = (entry: string, why: string): void => {
    warnings.push(`audit.config.json: ignored migrations entry ${shown(entry)} (${why})`);
  };
  const base = resolve(root);
  let realBase: string;
  try {
    realBase = realpathSync(base);
  } catch (e) {
    for (const entry of entries) drop(entry, `project root unreadable: ${errorCode(e)}`);
    return { dirs, warnings };
  }
  const seen = new Set<string>();
  for (const entry of entries) {
    if (entry === "" || entry.includes("\0")) {
      drop(entry, "not a path");
      continue;
    }
    if (isAbsolute(entry) || /^[A-Za-z]:/.test(entry) || entry.startsWith("\\")) {
      drop(entry, "absolute paths are allowed only in --migrations");
      continue;
    }
    if (entry.split(/[\\/]/).includes("..")) {
      drop(entry, '".." is allowed only in --migrations');
      continue;
    }
    const abs = resolve(base, entry);
    if (!inside(base, abs)) {
      drop(entry, "outside the project");
      continue;
    }
    let real: string;
    let isDir: boolean;
    try {
      real = realpathSync(abs);
      isDir = statSync(real).isDirectory();
    } catch (e) {
      drop(entry, errorCode(e) === "ENOENT" ? "not found" : errorCode(e));
      continue;
    }
    if (!inside(realBase, real)) {
      drop(entry, "a symlink out of the project");
      continue;
    }
    if (!isDir) {
      drop(entry, "not a directory");
      continue;
    }
    if (seen.has(real)) continue;
    if (seen.size >= MAX_REPO_MIGRATION_DIRS) {
      drop(entry, `at most ${MAX_REPO_MIGRATION_DIRS} directories`);
      continue;
    }
    seen.add(real);
    dirs.push(entry);
  }
  return { dirs, warnings };
}
