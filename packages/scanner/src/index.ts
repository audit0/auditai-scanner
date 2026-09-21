export { reachesFailOn, STATUS_RANK } from "./fail-on.js";
export {
  formatFinding,
  formatScanText,
  formatSnapshotText,
  isLead,
  LEADS_NOTE,
  printable,
  SNAPSHOT_LEADS_NOTE,
} from "./format.js";
export {
  type AuditConfig,
  readAuditConfig,
  runScan,
  ScanError,
  type ScanErrorCode,
  type ScanOptions,
  type ScanResult,
  type ScanSummary,
  summarize,
} from "./scan.js";
export {
  type RelationFacts,
  type SnapshotScanOptions,
  type SnapshotScanOutcome,
  type SnapshotScanResult,
  scanSnapshot,
  unwrapSnapshot,
} from "./scan-snapshot.js";
export { SNAPSHOT_QUERY } from "./snapshot-query.js";
