import {
  type CoverageSummary,
  type Finding,
  isBlocking,
  renderCoverageStatement,
  summarizeCoverage,
} from "@auditai/core";
import { deterministicFix } from "@auditai/fixes";
import { buildGraph } from "@auditai/graph";
import { type PolicyDetail, type ProjectModel, parseLiveSnapshot } from "@auditai/parser";
import {
  apiReaches,
  applyTiers,
  defaultRules,
  isTautology,
  isView,
  opensAccess,
  reachableByAnon,
  runRules,
} from "@auditai/rules";
import { type ScanSummary, summarize } from "./scan.js";

/**
 * A scan of a live database instead of a repository.
 *
 * The caller runs one read-only query in their own SQL editor (the snapshot query ships with the
 * product) and hands back its JSON. Everything the database-layer rules need is in it: which tables
 * have RLS, the policies in force with their roles and predicates, the SECURITY DEFINER functions and
 * who may execute them, the storage buckets. No repository, no install, no credentials, and no row of
 * the caller's data.
 *
 * Why this exists rather than only reading migrations: on 20 September 2026 only 10 of 30 real
 * Next.js + Supabase repositories could rebuild their schema from their own migrations, and the
 * engine's precision was 62% where they could against 27% where they could not
 * (docs/realworld/2026-09-20-schema-truth.md). A snapshot has no ordering to get wrong and no dynamic
 * SQL to evaluate: the database already ran all of it.
 *
 * What a snapshot cannot see is the application: there are no routes in it, so the rules about
 * service-role queries and mass assignment never fire. That is stated in the result rather than
 * hidden, because "no findings" from a snapshot means "nothing wrong in the database", never "this
 * application is safe".
 */

export interface SnapshotScanResult {
  summary: ScanSummary;
  findings: Finding[];
  coverage: CoverageSummary;
  coverageStatement: string;
  blocking: boolean;
  /**
   * A rule threw during evaluation (REVIEW.md #1): its findings are missing from this report, so
   * a clean result here is not proof the database is clean. The message is in `summary.warnings`.
   */
  incomplete: boolean;
  /** When the database reported the snapshot was taken. */
  takenAt: string;
  postgres: string;
  /** What this input cannot answer, in words for the report. */
  limits: string[];
  /**
   * Every policy exactly as the database reported it, keyed `table` (`storage.objects` for storage),
   * so a page can quote the line a finding is about and write the statement that restores it.
   */
  policies: Record<string, PolicyDetail[]>;
  /** Every function of the public schema: who may execute it, as the database reported the grants. */
  functions: Record<string, { securityDefiner: boolean; grantedTo: string[]; sqlName?: string }>;
  /**
   * Every relation by its key: the name exactly as Postgres stores it when that differs (a page must
   * write `"Post"`, not `post`), what kind it is, and what the API roles may do with it.
   */
  relations: Record<string, RelationFacts>;
  /**
   * Tables anyone can read every row of, because a policy says so: row level security on, a
   * permissive SELECT (or ALL) policy for anon or PUBLIC whose condition is `true`, and SELECT granted.
   * A fact, not a finding: a catalogue is meant to be read, a customers table is not, and only the
   * owner knows which this is. It is listed so that "nothing open" is never said above it.
   */
  publicReads: Array<{ table: string; policy: string }>;
}

export interface RelationFacts {
  sqlName?: string;
  kind?: string;
  grants?: { anon: string[]; authenticated: string[] };
}

export interface SnapshotScanOptions {
  now?: string;
  /** Tables the owner declares public on purpose; echoed in the summary, as in a repository scan. */
  publicTables?: readonly string[];
}

export type SnapshotScanOutcome =
  | { ok: true; result: SnapshotScanResult }
  | { ok: false; error: string };

const LIMITS = [
  "Application code was not read: the entry points here are the Data API endpoints your database serves, so nothing is said about service-role queries, missing authentication or mass assignment in your own routes.",
  "A clean result means the database refuses the accesses these rules test, not that the application is safe.",
  "A view that runs with its owner's rights over a table with row level security is a lead, not a headline: a view is often meant to publish a subset, and you decide. Foreign tables are not judged.",
];

/**
 * The rows inside what the Supabase MCP server's execute_sql returns: a sentence, the rows between
 * `<untrusted-data-…>` tags, another sentence. The opening tag is also named in the first sentence,
 * so the rows start after the last opening tag before the closing one.
 */
function insideUntrustedData(t: string): string | null {
  const close = /<\/untrusted-data-[\w-]+>/.exec(t);
  if (!close) return null;
  const tag = close[0].slice(2, -1);
  const open = t.lastIndexOf(`<${tag}>`, close.index);
  return open < 0 ? null : t.slice(open + tag.length + 2, close.index);
}

/**
 * SQL editors and agents hand the result back in several wrappings: the bare JSON, a one-row JSON
 * export (`[{"snapshot": {...}}]`), a CSV cell with doubled quotes, the Supabase MCP server's
 * execute_sql text, or an MCP content array around it. Accept all of them, since the person or agent
 * pasting it should not have to know which one they copied.
 */
export function unwrapSnapshot(text: string, depth = 0): string {
  const t = text.trim().replace(/^\uFEFF/, "");
  if (depth < 3) {
    const rows = insideUntrustedData(t);
    if (rows !== null) return unwrapSnapshot(rows, depth + 1);
  }
  try {
    const v: unknown = JSON.parse(t);
    // A JSON string holding the text again, or an MCP content array: [{ type: "text", text }].
    if (depth < 3 && typeof v === "string") return unwrapSnapshot(v, depth + 1);
    if (depth < 3 && Array.isArray(v) && v.length > 0) {
      const first = v[0] as Record<string, unknown> | null;
      if (
        first &&
        typeof first === "object" &&
        first.type === "text" &&
        typeof first.text === "string"
      )
        return unwrapSnapshot(first.text, depth + 1);
    }
    if (Array.isArray(v) && v.length === 1 && typeof v[0] === "object" && v[0] !== null) {
      const cell = (v[0] as Record<string, unknown>).snapshot;
      if (cell !== undefined) return typeof cell === "string" ? cell : JSON.stringify(cell);
    }
    if (typeof v === "object" && v !== null && "snapshot" in v) {
      const cell = (v as Record<string, unknown>).snapshot;
      return typeof cell === "string" ? cell : JSON.stringify(cell);
    }
    return t;
  } catch {
    // Not JSON as a whole: a CSV export is a header line and one quoted cell.
    const lines = t.split(/\r?\n/);
    const header = lines[0]?.trim().replace(/^"(.*)"$/, "$1");
    const cell = lines.length >= 2 && header === "snapshot" ? lines.slice(1).join("\n") : t;
    return cell.startsWith('"') && cell.endsWith('"')
      ? cell.slice(1, -1).replace(/""/g, '"')
      : cell;
  }
}

/**
 * A table with RLS off that carries policies is one cause: policies-without-rls-enabled says it, and
 * its fix is only the switch. table-without-rls would say it again with a fix that adds owner
 * policies next to the ones already there. A repository scan keeps both, because there the second
 * one is bound to a route of the application and the sandbox proves it through that route.
 */
function redundant(f: Finding, deadPolicies: ReadonlySet<string>): boolean {
  if (f.ruleId !== "supabase.table-without-rls") return false;
  const table = f.evidence.find((e) => e.kind === "rule")?.data?.table;
  return typeof table === "string" && deadPolicies.has(table);
}

/**
 * Runs the deterministic rules against a live-database snapshot, as pasted: the wrapping the SQL
 * editor added is removed first. No model call, no network.
 */
export function scanSnapshot(
  snapshotJson: string,
  opts: SnapshotScanOptions = {},
): SnapshotScanOutcome {
  const parsed = parseLiveSnapshot(unwrapSnapshot(snapshotJson));
  if (!parsed.ok) return { ok: false, error: parsed.error };
  const snap = parsed.model;

  const model: ProjectModel = {
    root: "<live schema snapshot>",
    files: [],
    routes: snap.dataApiRoutes,
    clientFactories: [],
    authHelpers: [],
    tables: snap.tables,
    exposures: [],
    fileIgnores: {},
    warnings: snap.notes,
    sqlFunctions: snap.sqlFunctions,
    storageBuckets: snap.storageBuckets,
    fromLiveDatabase: true,
    ...(snap.dataApiRefusesUnfilteredWrites === undefined
      ? {}
      : { dataApiRefusesUnfilteredWrites: snap.dataApiRefusesUnfilteredWrites }),
  };
  const graph = buildGraph(model);
  const publicTables = opts.publicTables ?? [];
  const deadPolicies = new Set(
    snap.tables.filter((t) => !t.rlsEnabled && t.policyDetails.length > 0).map((t) => t.table),
  );
  // Same pipeline as a repository scan: rules, then what the product may claim, then the schema fix
  // that follows from the facts alone. Only headlines get a fix here — a lead is not a hole we found.
  // runRules never throws: a broken rule is caught internally and reported as a warning on `model`
  // (rule.ts). Nothing else touches `model.warnings` across this call, so any warning that appears
  // here is that catch firing, and the scan below must not report itself as clean (REVIEW.md #1).
  const warningsBeforeRules = model.warnings.length;
  const ruleFindings = runRules(defaultRules, model, graph, {
    ...(opts.now === undefined ? {} : { now: opts.now }),
    publicTables,
  });
  const incomplete = model.warnings.length > warningsBeforeRules;
  const findings = applyTiers(ruleFindings)
    .filter((f) => !redundant(f, deadPolicies))
    // Numbered again after the filter, so the report reads AUDIT-001, AUDIT-002 without a gap.
    .map((f, i) => ({ ...f, id: `AUDIT-${String(i + 1).padStart(3, "0")}` }))
    .map((f) => {
      if (f.status === "suppressed" || f.tier === "lead") return f;
      const fix = deterministicFix(f, model);
      return fix ? { ...f, fix } : f;
    });
  const coverage = summarizeCoverage(findings);
  return {
    ok: true,
    result: {
      summary: summarize(model, defaultRules.length, publicTables),
      findings,
      coverage,
      coverageStatement: renderCoverageStatement(coverage),
      blocking: findings.some((f) => isBlocking(f)),
      incomplete,
      takenAt: snap.takenAt,
      postgres: snap.postgres,
      limits: LIMITS,
      policies: Object.fromEntries(snap.tables.map((t) => [t.table, t.policyDetails])),
      functions: Object.fromEntries(
        snap.sqlFunctions.map((f) => [
          f.name,
          {
            securityDefiner: f.securityDefiner,
            grantedTo: f.grantedTo,
            ...(f.sqlName !== undefined ? { sqlName: f.sqlName } : {}),
          },
        ]),
      ),
      relations: Object.fromEntries(
        snap.tables.map((t) => {
          const facts: RelationFacts = {};
          if (t.sqlName !== undefined) facts.sqlName = t.sqlName;
          if (t.kind !== undefined) facts.kind = t.kind;
          if (t.apiGrants !== undefined) facts.grants = t.apiGrants;
          return [t.table, facts];
        }),
      ),
      publicReads: snap.tables.flatMap((t) => {
        if (t.table.includes(".") || !t.rlsEnabled || isView(t)) return [];
        const open = t.policyDetails.find(
          (p) =>
            (p.command === "select" || p.command === "all") &&
            opensAccess(p) &&
            reachableByAnon(p) &&
            isTautology(p.using),
        );
        if (!open || !apiReaches(t, ["anon"], ["select"])) return [];
        return [{ table: t.table, policy: open.name }];
      }),
    },
  };
}
