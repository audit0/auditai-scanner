import { relative } from "node:path";
import type { Finding } from "@auditai/core";
import type { ScanResult } from "./scan.js";

/** The scanned root as the user would type it: relative to the working directory when it is inside it. */
function displayRoot(root: string): string {
  const rel = relative(process.cwd(), root);
  if (rel === "") return ".";
  return rel.startsWith("..") ? root : rel;
}

function loc(f: Finding): string {
  const first = f.evidence.find((e) => e.locations && e.locations.length > 0)?.locations?.[0];
  return first ? `${first.file}:${first.line}` : "";
}

function where(f: Finding): string {
  const seen = new Set<string>();
  for (const e of f.evidence) for (const l of e.locations ?? []) seen.add(`${l.file}:${l.line}`);
  return [...seen].join(", ");
}

export function formatFinding(f: Finding): string {
  const why = f.evidence.find((e) => e.kind === "rule")?.summary ?? "";
  const lines = [
    `${f.id}  ${f.status.toUpperCase()}  ${f.severity.toUpperCase()}  ${f.title}`,
    `  Entry   ${f.entrypoints.join(", ")}   ${loc(f)}`,
    `  Path    ${f.path.join(" -> ")}`,
    `  Why     ${why}`,
    `  Where   ${where(f)}`,
    `  Rule    ${f.ruleId} · ${(f.cwe ?? []).join(", ")} · confidence ${f.confidence.toFixed(2)}`,
  ];
  if (f.status === "suppressed") {
    const s = [...f.evidence].reverse().find((e) => e.data?.suppressed === true);
    if (s) lines.push(`  Ignored ${s.summary}`);
  }
  return lines.join("\n");
}

export function formatScanText(r: ScanResult): string {
  const s = r.summary;
  const out: string[] = [
    `Audit AI scan  ${displayRoot(s.root)}`,
    `Files ${s.files} · Routes ${s.routes} · Supabase queries ${s.queries} · Tables with RLS ${s.tablesWithRls}/${s.tablesKnown} · Rules ${s.rules}`,
  ];
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
    for (const f of r.findings) out.push(formatFinding(f), "");
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
