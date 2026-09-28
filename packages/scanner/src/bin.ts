#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { FINDING_STATUSES, type FindingStatus } from "@auditai/core";
import { reachesFailOn } from "./fail-on.js";
import { formatScanText, formatSnapshotText } from "./format.js";
import { runScan, ScanError, type ScanResult } from "./scan.js";
import { scanSnapshot } from "./scan-snapshot.js";
import { SNAPSHOT_QUERY } from "./snapshot-query.js";

const USAGE = `auditai-scan — deterministic security scan for Next.js + Supabase apps (open source)

Usage:
  auditai-scan [path] [--json] [--fail-on <status>] [--migrations <dir>]...
  auditai-scan --snapshot-query            print the read-only query to run in your SQL editor
  auditai-scan --snapshot <file> [--json]  scan your live database from that query's result

Options:
  --json               machine-readable output
  --fail-on <status>   exit 1 when a finding reaches this status (default: confirmed)
                       one of: candidate, likely, confirmed, verified. Leads never do.
  --migrations <dir>   extra directory with Supabase migration SQL (repeatable)
  --snapshot <file>    the JSON your SQL editor returned for --snapshot-query ("-" reads stdin).
                       Reads your database as it is, not as your migrations say it should be.
  -h, --help           show this help

Exit code: 0 clean, 1 a finding reached --fail-on or a rule crashed (report incomplete),
           2 usage error or <path> is not a directory

Config: <path>/audit.config.json { "ignore": ["evals/**"], "migrations": ["supabase/migrations"] }
Suppress a finding: // auditai:ignore <ruleId|*> -- reason   (above the handler or at the top of a file)
`;

function main(argv: string[]): number {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      "fail-on": { type: "string", default: "confirmed" },
      migrations: { type: "string", multiple: true, default: [] },
      snapshot: { type: "string" },
      "snapshot-query": { type: "boolean", default: false },
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
  if (values["snapshot-query"]) {
    process.stdout.write(SNAPSHOT_QUERY);
    return 0;
  }
  const snapshotFile = values.snapshot as string | undefined;
  if (snapshotFile !== undefined) {
    if (snapshotFile !== "-" && !existsSync(snapshotFile)) {
      process.stderr.write(`error: ${snapshotFile} does not exist\n`);
      return 2;
    }
    const text = readFileSync(snapshotFile === "-" ? 0 : snapshotFile, "utf8");
    const out = scanSnapshot(text);
    if (!out.ok) {
      // A snapshot we cannot read must never look like a database with nothing wrong in it.
      process.stderr.write(`error: not a snapshot this version understands: ${out.error}\n`);
      return 2;
    }
    process.stdout.write(
      values.json ? `${JSON.stringify(out.result, null, 2)}\n` : formatSnapshotText(out.result),
    );
    // A rule that crashed makes this report incomplete regardless of --fail-on: a security scan
    // must never exit 0 on a scan it did not finish (REVIEW.md #1).
    return reachesFailOn(out.result.findings, failOn as FindingStatus) || out.result.incomplete
      ? 1
      : 0;
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
  // A rule that crashed makes this report incomplete regardless of --fail-on: a security scan must
  // never exit 0 on a scan it did not finish (REVIEW.md #1).
  return reachesFailOn(result.findings, failOn as FindingStatus) || result.incomplete ? 1 : 0;
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (e) {
  process.stderr.write(`error: ${e instanceof Error ? e.message : String(e)}\n`);
  process.exitCode = 2;
}
