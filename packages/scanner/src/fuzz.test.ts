import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { routeFromFile } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { runScan, type ScanResult } from "./scan.js";

/**
 * Crash resistance on hostile input. A pull request can put anything into the files the GitHub check
 * scans; the check must end with a verdict, so runScan must return for every input. Every fixture's
 * sources (routes, libs, SQL, config) are mutated in deterministic ways and scanned; a throw anywhere
 * (parser, graph, rules) fails this test. The seed is printed on failure so a case can be replayed.
 */
const FIXTURES = fileURLToPath(new URL("../../../evals/fixtures/", import.meta.url));
const SOURCE = /\.(ts|tsx|js|jsx|mjs|cjs|sql|json|prisma)$/;
const SEED = Number(process.env.AUDITAI_FUZZ_SEED ?? 20260912);

/** mulberry32: small, seedable, good enough for picking offsets. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (name === "node_modules" || name === ".git") continue;
    if (readdirSyncSafe(p)) walk(p, out);
    else if (SOURCE.test(name)) out.push(p);
  }
  return out;
}

function readdirSyncSafe(p: string): boolean {
  try {
    readdirSync(p);
    return true;
  } catch {
    // A file, not a directory.
    return false;
  }
}

const fixtures = readdirSync(FIXTURES).filter((d) => existsSync(join(FIXTURES, d, "vulnerable")));

type Mutation = (text: string, random: () => number, rel: string) => string;

const truncate: Mutation = (text, random) => text.slice(0, Math.floor(random() * text.length));
const unbalanced: Mutation = (text, random) => {
  const at = Math.floor(random() * text.length);
  const brace = random() < 0.5 ? "{" : "}";
  return `${text.slice(0, at)}${brace.repeat(1 + Math.floor(random() * 3))}${text.slice(at)}`;
};
const nul: Mutation = (text, random) => {
  const at = Math.floor(random() * text.length);
  return `${text.slice(0, at)}\u0000\u0000${text.slice(at)}`;
};
const longLine: Mutation = (text) => `${text}\n// ${"x".repeat(1024 * 1024)}\n`;
const nested = (text: string, rel: string, depth: number): string => {
  const sql = rel.endsWith(".sql");
  const open = sql ? "(" : "{a:";
  const close = sql ? ")" : "}";
  return `${text}\n${sql ? "select " : "export const deep = "}${open.repeat(depth)}1${close.repeat(depth)};\n`;
};
/** Beyond what the TypeScript parser itself survives: the file must be skipped with a warning. */
const deepObject: Mutation = (text, _random, rel) =>
  nested(text, rel, rel.endsWith(".sql") ? 2000 : 5000);
/** Parses fine; our own walkers must not recurse themselves to death on it. */
const nestedObject: Mutation = (text, _random, rel) => nested(text, rel, 300);
const binaryNoise: Mutation = (_text, random) => {
  let out = "";
  for (let i = 0; i < 4096; i += 1) out += String.fromCharCode(Math.floor(random() * 0x3000));
  return out;
};
const emptyFile: Mutation = () => "";
const bom: Mutation = (text) => `\ufeff${text}`;

const MUTATIONS: Record<string, Mutation> = {
  truncate,
  unbalanced,
  nul,
  longLine,
  deepObject,
  nestedObject,
  binaryNoise,
  emptyFile,
  bom,
};

function copyFixture(name: string): { root: string; app: string; sql: string } {
  const root = mkdtempSync(join(tmpdir(), "auditai-fuzz-"));
  cpSync(join(FIXTURES, name, "vulnerable"), join(root, "vulnerable"), { recursive: true });
  if (existsSync(join(FIXTURES, name, "supabase")))
    cpSync(join(FIXTURES, name, "supabase"), join(root, "supabase"), { recursive: true });
  return { root, app: join(root, "vulnerable"), sql: join(root, "supabase") };
}

function scanCopy(copy: { app: string; sql: string }, label: string): ScanResult {
  let result: ScanResult;
  try {
    result = runScan(copy.app, { sqlDirs: existsSync(copy.sql) ? [copy.sql] : [] });
  } catch (e) {
    throw new Error(
      `runScan threw on ${label} (seed ${SEED}): ${e instanceof Error ? (e.stack ?? e.message) : String(e)}`,
    );
  }
  expect(result.summary.warnings, label).toBeInstanceOf(Array);
  expect(result.findings, label).toBeInstanceOf(Array);
  expect(typeof result.coverageStatement, label).toBe("string");
  return result;
}

describe.each(fixtures)("fuzz %s", (name) => {
  it.each(Object.keys(MUTATIONS))("survives %s applied to every source file", (kind) => {
    const copy = copyFixture(name);
    const random = rng(SEED + kind.length);
    try {
      const mutate = MUTATIONS[kind] as Mutation;
      for (const file of walk(copy.root)) {
        const rel = relative(copy.root, file);
        writeFileSync(file, mutate(readFileSync(file, "utf8"), random, rel));
      }
      scanCopy(copy, `${name}/${kind}`);
    } finally {
      rmSync(copy.root, { recursive: true, force: true });
    }
  });

  it("survives every file truncated on its own at three random offsets", () => {
    const random = rng(SEED);
    const original = walk(join(FIXTURES, name));
    for (const src of original) {
      const rel = relative(join(FIXTURES, name), src);
      // Only what copyFixture copies: the vulnerable app and the fixture's own migrations.
      if (!rel.startsWith("vulnerable/") && !rel.startsWith("supabase/")) continue;
      for (let i = 0; i < 3; i += 1) {
        const copy = copyFixture(name);
        try {
          const target = join(copy.root, rel);
          writeFileSync(target, truncate(readFileSync(target, "utf8"), random));
          scanCopy(copy, `${name}/${rel}#truncate${i}`);
        } finally {
          rmSync(copy.root, { recursive: true, force: true });
        }
      }
    }
  });
});

describe("fuzz: hostile trees built from scratch", () => {
  const scratch = (files: Record<string, string>): string => {
    const root = mkdtempSync(join(tmpdir(), "auditai-fuzz-"));
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      writeFileSync(join(root, rel), text);
    }
    return root;
  };

  const handler = [
    'import { createClient } from "@supabase/supabase-js";',
    "export async function GET(req: Request, { params }: { params: Record<string, string> }) {",
    "  const c = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);",
    '  const { data } = await c.from("t").select("*").eq("id", params.p0);',
    "  return Response.json(data);",
    "}",
  ].join("\n");

  it("a 500-segment route path, dynamic and group segments included", () => {
    const segments = Array.from({ length: 500 }, (_, i) =>
      i % 7 === 0 ? `[p${i}]` : i % 11 === 0 ? `(g${i})` : i % 13 === 0 ? `[...r${i}]` : `s${i}`,
    );
    const rel = `app/api/${segments.join("/")}/route.ts`;
    // Pure: the path never touches the file system (macOS caps paths at 1024 bytes).
    const route = routeFromFile(rel);
    expect(route).not.toBeNull();
    expect(route?.split("/").length).toBeGreaterThan(400);
  });

  it("the deepest route path the file system allows", () => {
    const root = mkdtempSync(join(tmpdir(), "auditai-fuzz-"));
    try {
      // As many segments as fit under the OS path limit (1024 bytes on macOS), at most 500.
      const segments: string[] = [];
      while (segments.length < 500 && root.length + segments.join("/").length < 880)
        segments.push(segments.length % 7 === 0 ? "[p]" : "s");
      const n = segments.length;
      expect(n).toBeGreaterThan(200);
      const rel = `app/api/${segments.join("/")}/route.ts`;
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      writeFileSync(join(root, rel), handler);
      writeFileSync(join(root, "package.json"), '{"name":"x","dependencies":{"next":"15.0.0"}}');
      const r = scanCopy({ app: root, sql: join(root, "nope") }, `${n}-segment route`);
      expect(r.summary.routes).toBe(1);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("malformed manifests, tsconfigs, audit.config.json and prisma schema", () => {
    const root = scratch({
      "package.json": "{ not json",
      "tsconfig.json":
        '{"compilerOptions":{"paths":{"@/*":["./*"]}}, "extends": "./tsconfig.json"}',
      "audit.config.json": '{"ignore": 5, "migrations": [1, "../../etc", "**/**/**/**"]}',
      "prisma/schema.prisma": "model { @@map(",
      "packages/a/package.json": '{"name": 5, "exports": {"./x": {"import": []}}}',
      "app/api/x/route.ts": "export async function GET() { return new Response('x'",
      "supabase/migrations/1.sql": "create table t (id int, ; $$ alter policy",
    });
    try {
      scanCopy({ app: root, sql: join(root, "supabase") }, "malformed manifests");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("deeply nested JSX, calls and template literals in a route", () => {
    const nested = `${"f(".repeat(3000)}1${")".repeat(3000)}`;
    const tpl = `${"`${".repeat(1500)}1${"}`".repeat(1500)}`;
    const root = scratch({
      "app/api/x/route.ts": `export async function GET() { const a = ${nested}; const b = ${tpl}; return Response.json({a, b}); }`,
      "app/deep/page.tsx": `export default function P() { return ${"<div>".repeat(2000)}x${"</div>".repeat(2000)}; }`,
    });
    try {
      scanCopy({ app: root, sql: join(root, "nope") }, "deep nesting");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
