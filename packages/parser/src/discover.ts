import { lstatSync, readdirSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";

/**
 * Files above this size are not source code we can reason about (bundles, generated data) and
 * would only cost parse time. Symlinks are never followed: a scanned repository must not be able
 * to point the scanner at files outside its own tree.
 */
const MAX_FILE_BYTES = 2 * 1024 * 1024;

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
  /** Prisma schema files (`*.prisma`), for model-to-table mapping. */
  prisma: string[];
  /** Rejected ignore globs and directories that could not be read. */
  warnings: string[];
}

/**
 * Ignore globs usually come from the scanned repository's own `audit.config.json`, so they are
 * untrusted input. They are matched segment by segment without regular expressions (a regex with
 * repeated `**` backtracks for seconds per path), and their shape is capped: a glob over these
 * limits is rejected with a warning rather than applied in part.
 */
export const GLOB_LIMITS = {
  /** Characters per glob. */
  maxLength: 256,
  /** `*` wildcards inside segments, per glob. */
  maxStars: 3,
  /** `**` segments per glob, after repeats are collapsed and a trailing one is dropped. */
  maxGlobstars: 1,
  /** Globs per scan; later ones are dropped. */
  maxPatterns: 64,
} as const;

const GLOBSTAR = "**";

/** Something that decides whether a project-relative path is ignored. A RegExp qualifies too. */
export interface PathMatcher {
  test(rel: string): boolean;
}

export interface GlobCheck {
  /** The glob as it is matched, or null when it is rejected. */
  glob: string | null;
  /** Why the glob was rejected or read differently from how it is written. */
  warning?: string;
}

function shown(glob: string): string {
  return JSON.stringify(glob.length > 80 ? `${glob.slice(0, 80)}...` : glob);
}

/**
 * Normalizes an ignore glob: `./` and empty segments dropped, repeated `**` segments collapsed into
 * one, a trailing `**` dropped (a directory pattern already matches everything below it), and a run
 * of `*` inside a segment read as a single `*`. Rejects globs over GLOB_LIMITS and globs that would
 * leave the whole project out of the scan.
 */
export function normalizeGlob(raw: string): GlobCheck {
  if (raw.length > GLOB_LIMITS.maxLength) {
    return {
      glob: null,
      warning: `ignore glob ${shown(raw)} rejected: longer than ${GLOB_LIMITS.maxLength} characters`,
    };
  }
  const segments: string[] = [];
  let inSegmentGlobstar = false;
  for (const part of raw.replace(/^\.\//, "").split("/")) {
    if (part === "") continue;
    const isGlobstar = part.length > 1 && /^\*+$/.test(part);
    const seg = isGlobstar ? GLOBSTAR : part.replace(/\*+/g, "*");
    if (!isGlobstar && seg !== part) inSegmentGlobstar = true;
    if (seg === GLOBSTAR && segments.at(-1) === GLOBSTAR) continue;
    segments.push(seg);
  }
  while (segments.at(-1) === GLOBSTAR) segments.pop();
  if (segments.length === 0) {
    return {
      glob: null,
      warning: `ignore glob ${shown(raw)} rejected: it would leave the whole project out of the scan`,
    };
  }
  let globstars = 0;
  let stars = 0;
  for (const seg of segments) {
    if (seg === GLOBSTAR) globstars += 1;
    else for (const ch of seg) if (ch === "*") stars += 1;
  }
  if (globstars > GLOB_LIMITS.maxGlobstars) {
    return {
      glob: null,
      warning: `ignore glob ${shown(raw)} rejected: more than ${GLOB_LIMITS.maxGlobstars} "**" segment`,
    };
  }
  if (stars > GLOB_LIMITS.maxStars) {
    return {
      glob: null,
      warning: `ignore glob ${shown(raw)} rejected: more than ${GLOB_LIMITS.maxStars} "*" wildcards`,
    };
  }
  const glob = segments.join("/");
  return inSegmentGlobstar
    ? {
        glob,
        warning: `ignore glob ${shown(raw)} read as ${shown(glob)}: "**" inside a segment matches like "*"`,
      }
    : { glob };
}

/** Normalizes a list of ignore globs, dropping rejected ones and everything past GLOB_LIMITS.maxPatterns. */
export function checkIgnoreGlobs(globs: readonly string[]): {
  globs: string[];
  warnings: string[];
} {
  const accepted = new Set<string>();
  const warnings: string[] = [];
  let dropped = 0;
  for (const raw of globs) {
    if (accepted.size >= GLOB_LIMITS.maxPatterns) {
      dropped += 1;
      continue;
    }
    const check = normalizeGlob(raw);
    if (check.warning) warnings.push(check.warning);
    if (check.glob !== null) accepted.add(check.glob);
  }
  if (dropped > 0) {
    warnings.push(
      `${dropped} ignore glob(s) dropped: at most ${GLOB_LIMITS.maxPatterns} are applied per scan`,
    );
  }
  return { globs: [...accepted], warnings };
}

/**
 * One path segment against one glob segment (`*` any run, `?` one character). Greedy with a single
 * backtrack point, so the cost is at most length(segment) x length(glob), never exponential.
 */
function matchSegment(glob: string, seg: string): boolean {
  if (!glob.includes("*") && !glob.includes("?")) return glob === seg;
  let g = 0;
  let s = 0;
  let starG = -1;
  let starS = 0;
  while (s < seg.length) {
    const ch = glob[g];
    if (ch === "*") {
      starG = g;
      starS = s;
      g += 1;
    } else if (g < glob.length && (ch === "?" || ch === seg[s])) {
      g += 1;
      s += 1;
    } else if (starG >= 0) {
      g = starG + 1;
      starS += 1;
      s = starS;
    } else {
      return false;
    }
  }
  while (glob[g] === "*") g += 1;
  return g === glob.length;
}

/**
 * Path segments against glob segments, where `**` stands for any number of segments. The same
 * greedy scheme one level up; a glob that is used up matches whatever lies below it.
 */
function matchSegments(glob: readonly string[], path: readonly string[]): boolean {
  let g = 0;
  let p = 0;
  let starG = -1;
  let starP = 0;
  for (;;) {
    if (g === glob.length) return true;
    const seg = glob[g] ?? "";
    if (seg === GLOBSTAR) {
      starG = g;
      starP = p;
      g += 1;
      continue;
    }
    const part = path[p];
    if (part !== undefined && matchSegment(seg, part)) {
      g += 1;
      p += 1;
      continue;
    }
    if (starG < 0 || starP >= path.length) return false;
    g = starG + 1;
    starP += 1;
    p = starP;
  }
}

/**
 * Compiles an ignore glob: `**` matches any path segments, `*` and `?` match within a segment.
 * Anchored at the project root; a directory pattern matches everything below it. Null when the
 * glob is rejected (see normalizeGlob).
 */
export function compileGlob(raw: string): PathMatcher | null {
  const { glob } = normalizeGlob(raw);
  if (glob === null) return null;
  const segments = glob.split("/");
  return { test: (rel: string): boolean => matchSegments(segments, rel.split("/")) };
}

export function isIgnored(rel: string, patterns: readonly PathMatcher[]): boolean {
  return patterns.some((p) => p.test(rel));
}

function errorCode(e: unknown): string {
  if (e instanceof Error && "code" in e && typeof e.code === "string") return e.code;
  return e instanceof Error ? e.message : String(e);
}

/**
 * Walks a project directory and returns source and SQL files, relative to root with forward slashes.
 * `extraSqlDirs` are additional directories (absolute, or relative to root) scanned for SQL only,
 * for projects that keep migrations outside the app directory. They are trusted as given: callers
 * must not pass directories named by the scanned repository without checking them first.
 */
export function discoverFiles(
  root: string,
  extraSqlDirs: readonly string[] = [],
  ignoreGlobs: readonly string[] = [],
): DiscoveredFiles {
  const source: string[] = [];
  const sql = new Set<string>();
  const manifests: string[] = [];
  const tsconfigs: string[] = [];
  const prisma: string[] = [];
  const checked = checkIgnoreGlobs(ignoreGlobs);
  const warnings = [...checked.warnings];
  const ignore = checked.globs.map(compileGlob).filter((m): m is PathMatcher => m !== null);
  const walk = (dir: string, sqlOnly = false): void => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch (e) {
      const rel = relative(root, dir).split(sep).join("/") || ".";
      warnings.push(`could not read directory ${rel}: ${errorCode(e)}`);
      return;
    }
    for (const name of entries) {
      const full = join(dir, name);
      let isDir: boolean;
      let size: number;
      try {
        const st = lstatSync(full);
        if (st.isSymbolicLink()) continue;
        isDir = st.isDirectory();
        size = st.size;
      } catch (e) {
        warnings.push(
          `could not stat ${relative(root, full).split(sep).join("/")}: ${errorCode(e)}`,
        );
        continue;
      }
      if (!isDir && size > MAX_FILE_BYTES) continue;
      if (isDir) {
        const relDir = relative(root, full).split(sep).join("/");
        if (!SKIP_DIRS.has(name) && !name.startsWith(".") && !isIgnored(relDir, ignore))
          walk(full, sqlOnly);
        continue;
      }
      const rel = relative(root, full).split(sep).join("/");
      if (isIgnored(rel, ignore)) continue;
      if (name.endsWith(".sql")) {
        sql.add(rel);
        continue;
      }
      if (sqlOnly || name.endsWith(".d.ts")) continue;
      if (name === "package.json") manifests.push(rel);
      else if (/^tsconfig(\..+)?\.json$/.test(name)) tsconfigs.push(rel);
      else if (name.endsWith(".prisma")) prisma.push(rel);
      else if (SOURCE_EXT.test(name)) source.push(rel);
    }
  };
  walk(root);
  for (const extra of extraSqlDirs) walk(resolve(root, extra), true);
  source.sort();
  manifests.sort();
  tsconfigs.sort();
  prisma.sort();
  return { source, sql: [...sql].sort(), manifests, tsconfigs, prisma, warnings };
}
