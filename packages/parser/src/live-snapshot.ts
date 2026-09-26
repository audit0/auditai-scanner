import type {
  ColumnInfo,
  FileRef,
  HttpMethod,
  PolicyCommand,
  PolicyDetail,
  QueryOperation,
  RlsTable,
  RouteHandler,
  SqlFunctionInfo,
  StorageBucket,
  SupabaseQuery,
} from "./model.js";
import { paramsReachingExecute } from "./sql-dynamic.js";

/**
 * A snapshot of a live Postgres database, read by the query in
 * `evals/realworld/schema-probe/live-snapshot.sql`, turned into the same facts the SQL rules already
 * consume from migration files.
 *
 * Why this input exists: on 20 September 2026, 10 of the 30 repositories of the fourth blind corpus
 * could rebuild their schema from their own migrations; half referenced tables their migrations never
 * create (docs/realworld/2026-09-20-schema-truth.md). Where the migrations are not the truth, the
 * engine reasons about a schema that does not exist, and precision drops from 62% to 27%. The database
 * knows the answer: which tables have RLS, which policies are in force, who may execute which
 * function. A snapshot needs no inference, no ordering, and no dynamic SQL evaluation.
 *
 * The snapshot carries catalog metadata only — never a row of the customer's data.
 */

/** Where a fact came from when it was read off a database rather than a file. */
export const SNAPSHOT_FILE = "<live schema snapshot>";
export const SNAPSHOT_REF: FileRef = { file: SNAPSHOT_FILE, line: 1 };

export interface SnapshotModel {
  tables: RlsTable[];
  /**
   * The Supabase Data API itself, as one entry point per table. PostgREST serves `/rest/v1/<table>`
   * for every table of an exposed schema to anyone holding the publishable key, so a table is
   * reachable whether or not the application ever queries it — a table the app forgot about is still
   * an endpoint. Rules that ask "which handler reaches this table" therefore have an honest answer
   * from a snapshot, and one the repository scan does not have: it only sees tables the code touches.
   */
  dataApiRoutes: RouteHandler[];
  sqlFunctions: SqlFunctionInfo[];
  storageBuckets: StorageBucket[];
  /** ISO timestamp the snapshot was taken, as the database reported it. */
  takenAt: string;
  /** `server_version`, e.g. "17.11". */
  postgres: string;
  /** What the snapshot could not express, in words for the report. */
  notes: string[];
  /** See `ProjectModel.dataApiRefusesUnfilteredWrites`; absent when the snapshot predates the field. */
  dataApiRefusesUnfilteredWrites?: boolean;
}

export type SnapshotResult = { ok: true; model: SnapshotModel } | { ok: false; error: string };

type Json = Record<string, unknown>;

const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string => (typeof v === "string" ? v : "");
const bool = (v: unknown): boolean => v === true;
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const strings = (v: unknown): string[] => arr(v).filter((x): x is string => typeof x === "string");

/** `public.users` -> `users`; every other schema keeps its prefix, as the rules key tables. */
function tableKey(schema: string, name: string): string {
  const lower = name.toLowerCase();
  return schema === "public" ? lower : `${schema}.${lower}`;
}

/** pg_policies.cmd is a word; a policy with no command covers all of them. */
function policyCommand(cmd: string): PolicyCommand {
  switch (cmd.trim().toUpperCase()) {
    case "SELECT":
      return "select";
    case "INSERT":
      return "insert";
    case "UPDATE":
      return "update";
    case "DELETE":
      return "delete";
    default:
      return "all";
  }
}

/**
 * pg_policies.roles arrives as a Postgres array, either already split by the JSON encoder or as the
 * literal `{anon,authenticated}`. A policy with no TO clause belongs to PUBLIC, which Postgres reports
 * as the role `public`.
 */
function policyRoles(v: unknown): string[] {
  const raw = Array.isArray(v)
    ? strings(v)
    : str(v)
        .replace(/^\{|\}$/g, "")
        .split(",");
  const roles = raw
    .map((r) => r.trim().replace(/^"|"$/g, "").toLowerCase())
    .filter((r) => r !== "");
  return roles.length > 0 ? roles : ["public"];
}

/** Postgres renders a missing predicate as SQL null; an empty string is not a predicate either. */
const predicate = (v: unknown): string | null => {
  const s = typeof v === "string" ? v.trim() : "";
  return s === "" ? null : s;
};

/**
 * The caller's identity inside a function body. Same reading as sql-functions.ts: `auth.role()` alone
 * is not a caller check, because every signed-in user has the same role.
 */
const CALLER_IN_BODY = /\bauth\s*\.\s*(uid|jwt|email)\s*\(|current_setting\s*\(\s*'request\.jwt/i;

/** `p_org uuid, p_user text DEFAULT auth.uid()` -> the input parameters an rpc body is keyed by. */
function parseArguments(text: string): {
  params: Array<{ name: string; type: string; default?: true }> | null;
  args: string;
  callerDefault: boolean;
} {
  const parts = splitTopLevel(text);
  const params: Array<{ name: string; type: string; default?: true }> = [];
  const types: string[] = [];
  let callerDefault = false;
  let named = true;
  for (const part of parts) {
    const p = part.trim();
    if (p === "") continue;
    // OUT and TABLE parameters are not inputs; INOUT is.
    const mode = /^(in|out|inout|variadic)\s+/i.exec(p);
    const rest = mode ? p.slice(mode[0].length) : p;
    if (mode && (mode[1] ?? "").toLowerCase() === "out") continue;
    // Both patterns start only where a run of whitespace starts and let `.` cross newlines, so a long
    // run of spaces cannot make them backtrack quadratically.
    const def = /(?<!\s)\s+default\s+(.+)$/is.exec(rest);
    const head = (def ? rest.slice(0, def.index) : rest).trim();
    if (def && CALLER_IN_BODY.test(def[1] ?? "")) callerDefault = true;
    const m = /^([A-Za-z_][\w$]*)\s+(.+)$/s.exec(head);
    if (!m) {
      named = false;
      types.push(head.toLowerCase());
      continue;
    }
    const type = (m[2] ?? "").trim().toLowerCase();
    types.push(type);
    params.push({
      name: (m[1] ?? "").toLowerCase(),
      type,
      ...(def ? { default: true as const } : {}),
    });
  }
  return { params: named ? params : null, args: types.join(", "), callerDefault };
}

/** Splits on commas that are not inside brackets or quotes. */
function splitTopLevel(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i] as string;
    if (quote !== null) {
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') quote = c;
    else if (c === "(" || c === "[") depth++;
    else if (c === ")" || c === "]") depth--;
    else if (c === "," && depth === 0) {
      out.push(text.slice(start, i));
      start = i + 1;
    }
  }
  out.push(text.slice(start));
  return out;
}

/** Relations named after FROM, JOIN, INSERT INTO, UPDATE or DELETE FROM in a function body. */
function relationsIn(body: string): string[] {
  const out = new Set<string>();
  const re =
    /\b(?:from|join|into|update|delete\s+from)\s+(?:only\s+)?((?:[A-Za-z_][\w$]*\s*\.\s*)?[A-Za-z_][\w$]*)/gi;
  for (const m of body.matchAll(re)) {
    const name = (m[1] ?? "").replace(/\s+/g, "").toLowerCase();
    if (name === "" || /^(select|values|table|lateral|unnest|generate_series)$/.test(name))
      continue;
    out.add(name.startsWith("public.") ? name.slice("public.".length) : name);
  }
  return [...out];
}

/**
 * Roles that can execute the function. Unlike the migration reader, nothing is assumed: the database
 * reported the grants that exist. PUBLIC implies every role, so anon and authenticated are listed too.
 */
function executeRoles(v: unknown): string[] {
  const raw = strings(v).map((r) => r.toLowerCase());
  const out: string[] = [];
  const hasPublic = raw.includes("public");
  if (hasPublic || raw.includes("anon")) out.push("anon");
  if (hasPublic || raw.includes("authenticated")) out.push("authenticated");
  for (const r of raw) if (!out.includes(r)) out.push(r);
  return out;
}

function readTable(v: unknown): RlsTable | null {
  if (!isObj(v)) return null;
  const schema = str(v.schema).toLowerCase();
  const name = str(v.name);
  if (name === "" || (schema !== "public" && schema !== "storage")) return null;
  const cols = arr(v.columns).filter(isObj);
  const columns = cols.map((c) => str(c.name).toLowerCase());
  const columnInfo: ColumnInfo[] = cols.map((c) => {
    const ref = isObj(c.references) ? c.references : null;
    const info: ColumnInfo = {
      name: str(c.name).toLowerCase(),
      type: str(c.type).toLowerCase() || "unknown",
      nullable: !bool(c.notNull),
      hasDefault: bool(c.hasDefault),
      references:
        ref && str(ref.table) !== ""
          ? { table: str(ref.table).toLowerCase(), column: str(ref.column).toLowerCase() }
          : null,
    };
    const raw = str(c.name);
    if (raw !== raw.toLowerCase()) info.sqlName = raw;
    return info;
  });
  const key = tableKey(schema, name);
  const table: RlsTable = {
    table: key,
    rlsEnabled: bool(v.rlsEnabled),
    policies: [],
    policyDetails: [],
    columns,
    columnInfo,
    location: SNAPSHOT_REF,
  };
  if (name !== name.toLowerCase()) table.sqlName = name;
  const kind = str(v.kind).toLowerCase();
  if (kind === "table" || kind === "partitioned" || kind === "view" || kind === "matview")
    table.kind = kind;
  if (Array.isArray(v.grants)) table.apiGrants = apiGrants(v.grants);
  if (Array.isArray(v.columnGrants)) table.apiColumnGrants = apiGrants(v.columnGrants);
  if ((kind === "view" || kind === "matview") && typeof v.securityInvoker === "boolean")
    table.viewSecurityInvoker = kind === "view" ? v.securityInvoker : false;
  if ((kind === "view" || kind === "matview") && Array.isArray(v.sources))
    table.viewSources = strings(v.sources).map((r) => r.toLowerCase());
  return table;
}

/** Words after UPDATE that name no table: `do update set`, `for update of|skip|nowait`, `update on`. */
const NOT_A_RELATION = new Set(["set", "of", "skip", "nowait", "only", "on", "or"]);

/** The words Postgres reads as false for a boolean setting, unique prefixes included. */
const OFF = /^(f|fa|fal|fals|false|n|no|of|off|0)$/i;

/**
 * Does the Data API refuse UPDATE and DELETE without WHERE? It does when `authenticator` preloads
 * safeupdate and nobody switched it off; `settings` come most specific first, as the query orders
 * them. No preload setting at all means the library is not loaded as far as the snapshot can tell.
 * Undefined when the snapshot has no such field (it was taken before the query read it).
 */
function refusesUnfilteredWrites(v: unknown): boolean | undefined {
  if (!Array.isArray(v)) return undefined;
  const settings = strings(v);
  const first = (name: string): string | undefined => {
    const s = settings.find((x) => x.startsWith(`${name}=`));
    return s?.slice(name.length + 1).trim();
  };
  // A PostgREST pre-request function runs before every request and can switch safeupdate off for it
  // (a SECURITY DEFINER one owned by postgres can, measured 24 September 2026); what it does is not
  // in the snapshot, so its presence alone means safeupdate cannot be counted on.
  const preRequest = first("pgrst.db_pre_request");
  if (preRequest !== undefined && preRequest.replace(/^['"]|['"]$/g, "") !== "") return false;
  const preload = first("session_preload_libraries");
  if (preload === undefined) return false;
  const loaded = preload
    .replace(/^"|"$/g, "")
    .split(",")
    .map((lib) =>
      lib
        .trim()
        .replace(/^['"]|['"]$/g, "")
        .replace(/^.*\//, "")
        .replace(/\.so$/, "")
        .toLowerCase(),
    )
    .includes("safeupdate");
  const enabled = first("safeupdate.enabled");
  return loaded && !(enabled !== undefined && OFF.test(enabled.replace(/^['"]|['"]$/g, "")));
}

const API_PRIVILEGES = new Set(["select", "insert", "update", "delete"]);

/** The table privileges anon and authenticated hold; a grant to PUBLIC counts for both. */
function apiGrants(v: readonly unknown[]): { anon: string[]; authenticated: string[] } {
  const out = { anon: new Set<string>(), authenticated: new Set<string>() };
  for (const g of v) {
    if (!isObj(g)) continue;
    const who = str(g.grantee).toLowerCase();
    const what = str(g.privilege).toLowerCase();
    if (!API_PRIVILEGES.has(what)) continue;
    if (who === "anon" || who === "public") out.anon.add(what);
    if (who === "authenticated" || who === "public") out.authenticated.add(what);
  }
  return { anon: [...out.anon], authenticated: [...out.authenticated] };
}

function readFunction(v: unknown): SqlFunctionInfo | null {
  if (!isObj(v)) return null;
  const schema = str(v.schema).toLowerCase();
  const exact = str(v.name);
  const bare = exact.toLowerCase();
  if (bare === "") return null;
  const body = str(v.body);
  const { params, args, callerDefault } = parseArguments(str(v.arguments));
  // The query sends a body only for SECURITY DEFINER functions; for the rest it sends `readsCaller`,
  // computed in the database with the same pattern, which is all the rules need from them.
  // The body is cut at 8,000 characters by the query; the flag is computed over the whole source, so
  // either one reading the caller is enough.
  const readsCaller = CALLER_IN_BODY.test(body) || bool(v.readsCaller);
  const fn: SqlFunctionInfo = {
    name: schema === "public" || schema === "" ? bare : `${schema}.${bare}`,
    securityDefiner: bool(v.securityDefiner),
    checksCaller: readsCaller || callerDefault,
    grantedTo: executeRoles(v.executeGrants),
    location: SNAPSHOT_REF,
  };
  const returns = str(v.returns).toLowerCase();
  if (returns !== "") fn.returns = returns;
  // The database always reports the argument list, so an empty one is known to be empty — a fix may
  // then name the function exactly as `f()` instead of asking the reader to fill it in.
  if (typeof v.arguments === "string") fn.args = args;
  if (typeof v.identity === "string") fn.identity = v.identity;
  if (exact !== bare) fn.sqlName = exact;
  if (params !== null) {
    fn.params = params;
    const injected = paramsReachingExecute(body, params);
    if (injected.length > 0) fn.sqlFromParams = injected;
  }
  const tables = relationsIn(body);
  if (tables.length > 0) fn.tables = tables;
  // Tables a function that is not SECURITY DEFINER updates, deletes from or merges into, as the
  // query reads them off its definition; `*` when it runs dynamic SQL next to such a word.
  const changes = [
    ...new Set(
      strings(v.changes).map((c) => {
        if (c === "*") return c;
        const parts = c
          .split(".")
          .map((x) => (x.startsWith('"') ? x.slice(1, -1) : x.toLowerCase()));
        const [first, second] = parts;
        return second === undefined || first === "public"
          ? (second ?? first ?? "").toLowerCase()
          : `${first}.${second}`.toLowerCase();
      }),
    ),
  ].filter((c) => c !== "" && !NOT_A_RELATION.has(c));
  if (changes.length > 0) fn.changes = changes;
  return fn;
}

/** Names called in a body, lowercase and without schema: `f(`, `public.f(`, `"f"(`. Linear in the body. */
function calledNames(body: string): Set<string> {
  const out = new Set<string>();
  for (const m of body.matchAll(/(?<![\w$"])"?([A-Za-z_][\w$]*)"?\s*\(/g))
    out.add((m[1] ?? "").toLowerCase());
  return out;
}

/**
 * A function that filters by another function of the same schema checks the caller when that one does.
 * The migration reader propagates the same way; here the call graph is the bodies in the snapshot.
 * Each body is read once, and each pass is a set lookup per call, so the cost is the size of the bodies.
 */
function propagateCallerChecks(fns: SqlFunctionInfo[], bodies: readonly string[]): void {
  const bare = (name: string): string => (name.split(".").pop() as string).toLowerCase();
  const calls = bodies.map(calledNames);
  const checking = new Set(fns.filter((f) => f.checksCaller).map((f) => bare(f.name)));
  for (let pass = 0; pass < 5; pass++) {
    let changed = false;
    fns.forEach((f, i) => {
      if (f.checksCaller) return;
      const own = bare(f.name);
      for (const name of calls[i] ?? []) {
        if (name === own || !checking.has(name)) continue;
        f.checksCaller = true;
        checking.add(own);
        changed = true;
        return;
      }
    });
    if (!changed) return;
  }
}

/** What PostgREST does with a table, and the HTTP method it answers on. */
const DATA_API_OPERATIONS: ReadonlyArray<{ op: QueryOperation; method: HttpMethod }> = [
  { op: "select", method: "GET" },
  { op: "insert", method: "POST" },
  { op: "update", method: "PATCH" },
  { op: "delete", method: "DELETE" },
];

/**
 * One entry point per table of the exposed schema. The client is `anon`: the publishable key is in
 * every browser bundle, so this is the weakest caller the Data API accepts, and RLS is the only thing
 * between it and the rows. Tables of other schemas (storage) are not served by the Data API and get
 * no route here; the storage rules judge those.
 */
function dataApiRoutes(tables: readonly RlsTable[]): RouteHandler[] {
  const out: RouteHandler[] = [];
  // The security graph keys a handler by its file and line, so every endpoint needs its own ref;
  // sharing one would collapse every table into a single node and hide all but one table's findings.
  let line = 0;
  for (const t of tables) {
    if (t.table.includes(".")) continue;
    // PostgREST serves a table under its exact name: `"Post"` is /rest/v1/Post, not /rest/v1/post.
    const path = `/rest/v1/${encodeURIComponent(t.sqlName ?? t.table)}`;
    for (const { op, method } of DATA_API_OPERATIONS) {
      line += 1;
      // An operation neither API role holds a privilege for is refused before any policy runs, so it
      // is no entry point. With the grants unknown, the Supabase default holds: both roles have all.
      const g = t.apiGrants;
      const client =
        !g || g.anon.includes(op) ? "anon" : g.authenticated.includes(op) ? "user_scoped" : null;
      if (client === null) continue;
      const ref: FileRef = { file: SNAPSHOT_FILE, line };
      const query: SupabaseQuery = {
        table: t.table,
        operation: op,
        client,
        clientName: client === "anon" ? "supabase (publishable key)" : "supabase (signed-in user)",
        clientLocation: ref,
        filters: [],
        payload: null,
        location: ref,
        text: `${method} ${path}`,
      };
      out.push({
        kind: "route",
        route: path,
        method,
        entry: `${method} ${path} (Supabase Data API)`,
        location: ref,
        inputs: [],
        authChecks: [],
        queries: [query],
        metadataAccesses: [],
        ignores: [],
      });
    }
  }
  return out;
}

/**
 * What one snapshot may hold. A real project is far below every one of these (Audit AI's own: 24
 * relations, 2 functions, 50 KB); above them the input is not a database anyone runs, and reading it
 * would only cost time. Refused as a whole, never cut: a partial read could hide the one open table.
 */
export const SNAPSHOT_LIMITS = {
  tables: 5_000,
  policies: 20_000,
  functions: 10_000,
  buckets: 5_000,
  /** A policy condition or an argument list. The longest real ones are a few hundred characters. */
  text: 20_000,
} as const;

/** The query sends at most 8,000 characters of a body; more than that was not produced by it. */
const MAX_BODY = 16_000;

function oversized(raw: Record<string, unknown>): string | null {
  const counts = {
    tables: arr(raw.tables).length,
    policies: arr(raw.policies).length,
    functions: arr(raw.functions).length,
    buckets: arr(raw.buckets).length,
  };
  for (const [kind, n] of Object.entries(counts)) {
    const max = SNAPSHOT_LIMITS[kind as keyof typeof counts];
    if (n > max) return `too large: ${n} ${kind}, more than the ${max} one snapshot may hold`;
  }
  const long = (v: unknown): boolean => typeof v === "string" && v.length > SNAPSHOT_LIMITS.text;
  for (const p of arr(raw.policies))
    if (isObj(p) && (long(p.using) || long(p.withCheck) || long(p.name)))
      return `too large: a policy longer than ${SNAPSHOT_LIMITS.text} characters`;
  for (const f of arr(raw.functions))
    if (isObj(f) && (long(f.arguments) || long(f.name) || long(f.returns)))
      return `too large: a function signature longer than ${SNAPSHOT_LIMITS.text} characters`;
  for (const t of arr(raw.tables)) if (isObj(t) && long(t.name)) return "too large: a table name";
  return null;
}

/** Parses the JSON the snapshot query produces. Never throws; a malformed snapshot is an error result. */
export function parseLiveSnapshot(text: string): SnapshotResult {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    return { ok: false, error: `not JSON: ${e instanceof Error ? e.message.slice(0, 120) : "?"}` };
  }
  if (!isObj(raw)) return { ok: false, error: "snapshot is not an object" };
  if (raw.snapshotVersion !== 1)
    return { ok: false, error: `unsupported snapshotVersion ${String(raw.snapshotVersion)}` };
  if (!Array.isArray(raw.tables) || !Array.isArray(raw.policies))
    return { ok: false, error: "snapshot has no tables or policies" };
  const tooLarge = oversized(raw);
  if (tooLarge) return { ok: false, error: tooLarge };

  const notes: string[] = [];
  const tables = new Map<string, RlsTable>();
  for (const t of raw.tables) {
    const table = readTable(t);
    if (table) tables.set(table.table, table);
  }

  let orphanPolicies = 0;
  for (const p of arr(raw.policies)) {
    if (!isObj(p)) continue;
    const key = tableKey(str(p.schema).toLowerCase(), str(p.table));
    const table = tables.get(key);
    if (!table) {
      orphanPolicies++;
      continue;
    }
    const detail: PolicyDetail = {
      name: str(p.name),
      command: policyCommand(str(p.command)),
      roles: policyRoles(p.roles),
      using: predicate(p.using),
      check: predicate(p.withCheck),
      location: SNAPSHOT_REF,
    };
    // pg_policies.permissive is the word PERMISSIVE or RESTRICTIVE; a boolean is accepted too.
    if (str(p.permissive).toUpperCase() === "RESTRICTIVE" || p.permissive === false)
      detail.permissive = false;
    table.policies.push(detail.name);
    table.policyDetails.push(detail);
  }
  if (orphanPolicies > 0)
    notes.push(`${orphanPolicies} policies on relations outside the snapshot`);

  // One body per entry, not per name: overloads share a name and each has its own body.
  const bodies: string[] = [];
  const sqlFunctions: SqlFunctionInfo[] = [];
  for (const f of arr(raw.functions)) {
    const fn = readFunction(f);
    if (!fn) continue;
    sqlFunctions.push(fn);
    bodies.push(isObj(f) ? str(f.body).slice(0, MAX_BODY) : "");
  }
  propagateCallerChecks(sqlFunctions, bodies);

  const storageBuckets: StorageBucket[] = arr(raw.buckets)
    .filter(isObj)
    .map((b) => ({ id: str(b.id), public: bool(b.public), location: SNAPSHOT_REF }))
    .filter((b) => b.id !== "");

  const refuses = refusesUnfilteredWrites(raw.apiSettings);
  return {
    ok: true,
    model: {
      tables: [...tables.values()],
      dataApiRoutes: dataApiRoutes([...tables.values()]),
      sqlFunctions,
      storageBuckets,
      takenAt: str(raw.takenAt),
      postgres: str(raw.postgres),
      notes,
      ...(refuses === undefined ? {} : { dataApiRefusesUnfilteredWrites: refuses }),
    },
  };
}
