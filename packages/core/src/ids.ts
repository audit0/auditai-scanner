/**
 * Identifier shapes shared by every adapter (CLI store, MCP, GitHub check, web routes). One source
 * so a path or query built from an id is validated the same way everywhere. `scripts/prove-lib.mjs`
 * runs with nothing installed and keeps literal copies; scripts/prove-lib.test.mjs pins them to these.
 */

/** Finding ids as the rules mint them (`AUDIT-001`) and as tools accept them: a rule prefix, a dash, digits. */
export const FINDING_ID = /^[A-Z][A-Z0-9]{0,15}-\d{3,7}$/;

/** Finding ids of the hosted scanner only (`AUDIT-` plus 3 to 7 digits): what report pages and their API accept. */
export const HOSTED_FINDING_ID = /^AUDIT-\d{3,7}$/;

/** Postgres gen_random_uuid() values in lowercase: report ids, proof job ids, scan attempts. */
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
