#!/usr/bin/env node
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { FINDING_STATUSES, type FindingStatus } from "@auditai/core";
import { formatScanText } from "./format.js";
import { runScan, ScanError, type ScanResult } from "./scan.js";

const USAGE = `auditai-scan — deterministic security scan for Next.js + Supabase apps (open source)

Usage:
  auditai-scan [path] [--json] [--fail-on <status>] [--migrations <dir>]...

Options:
  --json               machine-readable output
  --fail-on <status>   exit 1 when a finding reaches this status (default: confirmed)
                       one of: candidate, likely, confirmed, verified
  --migrations <dir>   extra directory with Supabase migration SQL (repeatable)
  -h, --help           show this help

Exit code: 0 clean, 1 a finding reached --fail-on, 2 usage error or <path> is not a directory

Config: <path>/audit.config.json { "ignore": ["evals/**"], "migrations": ["supabase/migrations"] }
Suppress a finding: // auditai:ignore <ruleId|*> -- reason   (above the handler or at the top of a file)
`;

const RANK: Record<FindingStatus, number> = {
  suppressed: -1,
  unverified: -1,
  candidate: 0,
  likely: 1,
  confirmed: 2,
  fix_proposed: 2,
  fix_applied: 2,
  verified: 3,
};

function main(argv: string[]): number {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      "fail-on": { type: "string", default: "confirmed" },
      migrations: { type: "string", multiple: true, default: [] },
      help: { type: "boolean", short: "h", default: false },
    },
  });
  if (values.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  const failOn = values["fail-on"] as string;
  if (!(FINDING_STATUSES as readonly string[]).includes(failOn)) {
    process.stderr.write(`error: --fail-on must be one of ${FINDING_STATUSES.join(", ")}\n`);
    return 2;
  }
  const migrations = (values.migrations as string[]).map((m) => resolve(m));
  let result: ScanResult;
  try {
    result = runScan(positionals[0] ?? ".", migrations.length > 0 ? { sqlDirs: migrations } : {});
  } catch (e) {
    // A path that cannot be scanned is a usage error, not an empty project: nothing on stdout.
    if (!(e instanceof ScanError)) throw e;
    process.stderr.write(`error: ${e.message}\n`);
    return 2;
  }
  process.stdout.write(
    values.json ? `${JSON.stringify(result, null, 2)}\n` : formatScanText(result),
  );
  const threshold = RANK[failOn as FindingStatus];
  return result.findings.some((f) => RANK[f.status] >= 0 && RANK[f.status] >= threshold) ? 1 : 0;
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (e) {
  process.stderr.write(`error: ${e instanceof Error ? e.message : String(e)}\n`);
  process.exitCode = 2;
}
