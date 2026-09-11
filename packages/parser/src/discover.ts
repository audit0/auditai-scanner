import { readdirSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";

const SKIP_DIRS = new Set([
  "node_modules",
  ".next",
  "dist",
  ".git",
  ".vercel",
  ".supabase",
  "coverage",
  ".turbo",
  "build",
  "out",
]);
const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;

export interface DiscoveredFiles {
  source: string[];
  sql: string[];
  /** package.json files inside the project (workspace packages for import resolution). */
  manifests: string[];
  /** tsconfig*.json files inside the project (`paths` aliases). */
  tsconfigs: string[];
}

/** Minimal glob: `**` matches any path segment(s), `*` matches within a segment. Anchored at the project root; a directory pattern matches everything below it. */
export function globToRegExp(glob: string): RegExp {
  const g = glob.replace(/^\.\//, "").replace(/\/$/, "");
  let re = "";
  let i = 0;
  while (i < g.length) {
    if (g.startsWith("**/", i)) {
      re += "(?:.*/)?";
      i += 3;
    } else if (g.startsWith("/**", i) && i + 3 === g.length) {
      re += "(?:/.*)?";
      i += 3;
    } else if (g.startsWith("**", i)) {
      re += ".*";
      i += 2;
    } else if (g[i] === "*") {
      re += "[^/]*";
      i += 1;
    } else if (g[i] === "?") {
      re += "[^/]";
      i += 1;
    } else {
      re += (g[i] ?? "").replace(/[.+^${}()|[\]\\]/g, "\\$&");
      i += 1;
    }
  }
  return new RegExp(`^${re}(?:/.*)?$`);
}

export function isIgnored(rel: string, patterns: readonly RegExp[]): boolean {
  return patterns.some((p) => p.test(rel));
}

/**
 * Walks a project directory and returns source and SQL files, relative to root with forward slashes.
 * `extraSqlDirs` are additional directories (absolute, or relative to root) scanned for SQL only,
 * for projects that keep migrations outside the app directory.
 */
export function discoverFiles(
  root: string,
  extraSqlDirs: readonly string[] = [],
  ignoreGlobs: readonly string[] = [],
): DiscoveredFiles {
  const source: string[] = [];
  const sql: string[] = [];
  const manifests: string[] = [];
  const tsconfigs: string[] = [];
  const ignore = ignoreGlobs.map(globToRegExp);
  const walk = (dir: string, sqlOnly = false): void => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries) {
      const full = join(dir, name);
      let isDir: boolean;
      try {
        isDir = statSync(full).isDirectory();
      } catch {
        continue;
      }
      if (isDir) {
        const relDir = relative(root, full).split(sep).join("/");
        if (!SKIP_DIRS.has(name) && !name.startsWith(".") && !isIgnored(relDir, ignore))
          walk(full, sqlOnly);
        continue;
      }
      const rel = relative(root, full).split(sep).join("/");
      if (isIgnored(rel, ignore)) continue;
      if (name.endsWith(".sql")) {
        if (!sql.includes(rel)) sql.push(rel);
        continue;
      }
      if (sqlOnly || name.endsWith(".d.ts")) continue;
      if (name === "package.json") manifests.push(rel);
      else if (/^tsconfig(\..+)?\.json$/.test(name)) tsconfigs.push(rel);
      else if (SOURCE_EXT.test(name)) source.push(rel);
    }
  };
  walk(root);
  for (const extra of extraSqlDirs) walk(resolve(root, extra), true);
  source.sort();
  sql.sort();
  manifests.sort();
  tsconfigs.sort();
  return { source, sql, manifests, tsconfigs };
}
