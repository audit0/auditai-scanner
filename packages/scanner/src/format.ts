import { relative } from "node:path";
import type { Finding } from "@auditai/core";
import { SNAPSHOT_FILE } from "@auditai/parser";
import type { ScanResult } from "./scan.js";
import type { SnapshotScanResult } from "./scan-snapshot.js";

/** The scanned root as the user would type it: relative to the working directory when it is inside it. */
function displayRoot(root: string): string {
  const rel = relative(process.cwd(), root);
  if (rel === "") return ".";
  return rel.startsWith("..") ? root : rel;
}

/**
 * Locations a reader can open. A live snapshot has no file: its entries carry a placeholder whose
 * line numbers only keep the Data API endpoints apart, so they are left out of what is printed.
 */
function openable(f: Finding): { file: string; line: number }[] {
  return f.evidence.flatMap((e) => e.locations ?? []).filter((l) => l.file !== SNAPSHOT_FILE);
}

function loc(f: Finding): string {
  const first = openable(f)[0];
  return first ? `${first.file}:${first.line}` : "";
}

function where(f: Finding): string {
  return [...new Set(openable(f).map((l) => `${l.file}:${l.line}`))].join(", ");
}

/** The added lines of a one-file diff, without the `+`, ready to paste into a migration. */
function fixBody(diff: string): string[] {
  return diff
    .split("\n")
    .filter((l) => l.startsWith("+") && !l.startsWith("+++"))
    .map((l) => l.slice(1));
}

/**
 * What a reader is told about the leads, wherever they are listed. The figure is measured: code-layer
 * and weak database rules were right 62 times out of 249 on four blind samples (tiers.ts).
 */
export const LEADS_NOTE =
  "From your application code. We did not check these: on code we have never seen, about one in four turns out to be real. They are places to look, not holes we found.";

/**
 * What a reader of a database check is told about its leads. They come from the weaker database
 * rules (a policy that never names the caller, a storage policy that only checks the bucket), not
 * from application code, which a snapshot does not contain.
 */
export const SNAPSHOT_LEADS_NOTE =
  "Weaker signals from your database: a policy that never names the caller, a storage policy that checks only the bucket. Many are on purpose, like a public catalogue or a shared bucket. They are places to look, not holes we proved.";

/**
 * Text that came from a database or a repository, made safe to print: control characters (a newline
 * that would start a forged report line, an escape sequence that would clear the terminal) are shown
 * as escapes instead of acting.
 */
export function printable(s: string): string {
  return [...s]
    .map((c) => {
      const n = c.charCodeAt(0);
      const control = n < 0x20 || (n >= 0x7f && n <= 0x9f) || n === 0x2028 || n === 0x2029;
      return control ? `\\u${n.toString(16).padStart(4, "0")}` : c;
    })
    .join("");
}

export function isLead(f: Finding): boolean {
  return f.tier === "lead";
}

export function formatFinding(f: Finding): string {
  const why = printable(f.evidence.find((e) => e.kind === "rule")?.summary ?? "");
  // A lead says so in its first word, and keeps the rule's own rating visible next to the capped one.
  const head = isLead(f)
    ? `${f.id}  LEAD  ${f.severity.toUpperCase()}${f.ruleSeverity ? ` (rule: ${f.ruleSeverity})` : ""}  ${printable(f.title)}`
    : `${f.id}  ${f.status.toUpperCase()}  ${f.severity.toUpperCase()}  ${printable(f.title)}`;
  const at = loc(f);
  const lines = [
    head,
    `  Entry   ${printable(f.entrypoints.join(", "))}${at === "" ? "" : `   ${printable(at)}`}`,
    `  Path    ${printable(f.path.join(" -> "))}`,
    `  Why     ${why}`,
  ];
  const whereAt = where(f);
  if (whereAt !== "") lines.push(`  Where   ${printable(whereAt)}`);
  lines.push(
    `  Rule    ${f.ruleId} · ${(f.cwe ?? []).join(", ")} · confidence ${f.confidence.toFixed(2)}`,
  );
  if (f.status === "suppressed") {
    const s = [...f.evidence].reverse().find((e) => e.data?.suppressed === true);
    if (s) lines.push(`  Ignored ${printable(s.summary)}`);
  }
  // A fix that follows from the schema alone: the migration itself, so it can be copied out of
  // the terminal. Findings whose fix depends on application code carry none.
  if (f.fix) {
    lines.push(`  Fix     ${printable(f.fix.summary)} (${f.fix.touchedFiles.join(", ")})`);
    for (const line of fixBody(f.fix.diff)) lines.push(`          ${printable(line)}`);
  }
  return lines.join("\n");
}

/** Headline findings as they are; the leads after them, under a heading that says what they are. */
function pushTiered(out: string[], findings: readonly Finding[], note = LEADS_NOTE): void {
  const leads = findings.filter(isLead);
  for (const f of findings.filter((x) => !isLead(x))) out.push(formatFinding(f), "");
  if (leads.length === 0) return;
  out.push(`Leads (${leads.length}). ${note}`, "");
  for (const f of leads) out.push(formatFinding(f), "");
}

/**
 * A scan of a live database. It names what was read (a schema at a moment in time) and what was not
 * (the application), because a clean database is not a safe application and the page must not imply it.
 */
export function formatSnapshotText(r: SnapshotScanResult): string {
  const s = r.summary;
  const taken = r.takenAt === "" ? "" : `  taken ${r.takenAt}`;
  const out: string[] = [
    `Audit AI database scan${taken}`,
    `Postgres ${r.postgres || "unknown"} · Tables ${s.tablesKnown} · With RLS ${s.tablesWithRls}/${s.tablesKnown} · Rules ${s.rules}`,
    "",
  ];
  if (r.incomplete) {
    out.push(
      "INCOMPLETE SCAN: a rule crashed before finishing (see warning below). This report is missing findings, not clean.",
      "",
    );
  }
  const reads = r.publicReads;
  if (r.findings.length === 0 && reads.length === 0)
    out.push(
      `Nothing to report: ${s.tablesKnown} table${s.tablesKnown === 1 ? "" : "s"} checked.`,
      "",
    );
  else if (r.findings.length > 0) pushTiered(out, r.findings, SNAPSHOT_LEADS_NOTE);
  if (reads.length > 0) {
    out.push(
      `Readable by anyone (${reads.length}): a policy lets every visitor read every row. Right for a public catalogue, wrong for anything personal.`,
    );
    for (const p of reads)
      out.push(`  public.${printable(p.table)}  policy "${printable(p.policy)}"`);
    out.push("");
  }
  out.push(r.coverageStatement, "");
  for (const l of r.limits) out.push(`Note: ${l}`);
  for (const w of s.warnings) out.push(`warning: ${w}`);
  return `${out.join("\n")}\n`;
}

export function formatScanText(r: ScanResult): string {
  const s = r.summary;
  const out: string[] = [
    `Audit AI scan  ${displayRoot(s.root)}`,
    `Files ${s.files} · Routes ${s.routes} · Supabase queries ${s.queries} · Tables with RLS ${s.tablesWithRls}/${s.tablesKnown} · Rules ${s.rules}`,
  ];
  if (r.incomplete) {
    out.push(
      "INCOMPLETE SCAN: a rule crashed before finishing (see warning below). This report is missing findings, not clean.",
    );
  }
  if (s.publicTables.length > 0) {
    // The declaration is never silent: what it suppressed is counted next to it.
    const n = r.findings.filter((f) => f.evidence.some((e) => e.data?.publicTables)).length;
    out.push(
      `Declared public in audit.config.json: ${s.publicTables.join(", ")} (${n} read-only finding${n === 1 ? "" : "s"} suppressed by the declaration; write paths are never covered)`,
    );
  }
  out.push("");
  if (r.findings.length === 0) {
    out.push(
      `No findings. ${s.routes} route${s.routes === 1 ? "" : "s"} and ${s.queries} quer${s.queries === 1 ? "y" : "ies"} checked.`,
    );
  } else {
    pushTiered(out, r.findings);
  }
  out.push("", r.coverageStatement);
  const likely = r.findings.filter((f) => f.status === "likely" || f.status === "candidate").length;
  if (likely > 0) {
    out.push(
      `${likely} likely finding${likely === 1 ? "" : "s"} await${likely === 1 ? "s" : ""} reasoning and sandbox verification (the hosted Audit AI step, auditai.sh).`,
    );
  }
  out.push(r.blocking ? "Blocking findings present." : "No blocking findings.");
  for (const w of s.warnings) out.push(`warning: ${w}`);
  return `${out.join("\n")}\n`;
}
