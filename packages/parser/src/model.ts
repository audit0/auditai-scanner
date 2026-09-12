/** Parser output: a framework-aware model of a Next.js + Supabase project. Syntactic, no type checker. */

export interface FileRef {
  /** Path relative to the scanned project root, forward slashes. */
  file: string;
  /** 1-based line. */
  line: number;
}

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";
export const HTTP_METHODS: readonly HttpMethod[] = [
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
];

/**
 * How a client reaches the database, which decides whether RLS applies. `direct_db` is a Drizzle or
 * Prisma connection: it bypasses PostgREST, so Supabase RLS does not apply unless the app sets the
 * authenticated role itself; for authorization it behaves like the service role.
 */
export type ClientKind = "service_role" | "anon" | "user_scoped" | "direct_db" | "unknown";

export interface ClientFactory {
  name: string;
  kind: ClientKind;
  location: FileRef;
  evidence: string;
}

export interface AuthHelper {
  name: string;
  location: FileRef;
  evidence: string;
}

export type InputKind = "route_param" | "body" | "query" | "header" | "action_arg";

export interface InputSource {
  kind: InputKind;
  name: string;
  location: FileRef;
}

export interface QueryFilter {
  method: string;
  column: string | null;
  valueText: string;
  /** True when the filter value is derived from a user-controlled input of the handler. */
  inputDerived: boolean;
}

export type QueryOperation =
  | "select"
  | "insert"
  | "update"
  | "delete"
  | "upsert"
  | "rpc"
  | "unknown";

/** The row payload passed to insert/update/upsert. */
export interface QueryPayload {
  text: string;
  inputDerived: boolean;
  /** True when the whole request input object is written as-is (no allow-list). */
  wholeInput: boolean;
}

/**
 * A Supabase Storage call `<client>.storage.from(bucket).<op>(path, …)`. Storage objects are rows of
 * `storage.objects`, so storage policies apply to anon/user-scoped clients and the service role skips them.
 */
export interface StorageAccess {
  /** Bucket id, or null when it is not a literal (or a same-file string constant). */
  bucket: string | null;
  /** download, upload, update, move, copy, remove, list, createSignedUrl, createSignedUrls, createSignedUploadUrl. */
  op: string;
  /** Source text of the path argument(s); both paths for move/copy. */
  pathText: string;
  /** True when a path argument is derived from user-controlled input of the entry point. */
  pathInputDerived: boolean;
  /**
   * True when every user-controlled path argument contains the caller's user or tenant id from the session
   * (`${user.id}/${name}`), or is checked against it (`path.startsWith(`${user.id}/`)`).
   */
  pathScopedToCaller: boolean;
}

/**
 * An earlier read of the same row, in the same entry point (or a helper it calls), filtered by the same
 * id value: `requireOwnership(id)` selecting `flows.id = id` through RLS before a service-role delete of
 * `flows.id = id`. Whether it ties the row to the caller is the rules' call (RLS policies, scope filters).
 */
export interface QueryGuard {
  location: FileRef;
  table: string;
  client: ClientKind;
  clientName: string | null;
  /** Every filter of the guard read; a scope column filtered by a session value ties it to the caller. */
  filters: QueryFilter[];
  /** The column the guard and the guarded query both filter by the same value. */
  column: string;
  /** A missing row stops the entry point: a throw or redirect, or a return every caller up to the entry point checks. */
  exitsWhenMissing: boolean;
  text: string;
  via?: string[];
  /**
   * Comparisons of the row's columns made in code after the read, each in an `if` that stops the
   * entry point: `if (!existing || existing.user_id !== user.id) return 404` gives
   * `{ method: "compare", column: "user_id", valueText: "user.id" }`.
   */
  checks?: QueryFilter[];
  /**
   * Set when the guard read is of a parent row: the guarded query filters by a column that refers
   * to the guard's table (`automation_steps.automation_id` -> `automations.id`), by a foreign key
   * in the migrations or by the column's name.
   */
  parent?: { table: string; column: string; how: "foreign key" | "column name" };
}

export interface SupabaseQuery {
  table: string;
  operation: QueryOperation;
  client: ClientKind;
  clientName: string | null;
  clientLocation: FileRef | null;
  filters: QueryFilter[];
  payload: QueryPayload | null;
  location: FileRef;
  text: string;
  /** Helper calls between the entry point and the query, e.g. `loadInvoice (packages/invoices/src/server.ts:12)`. */
  via?: string[];
  /** Set for Supabase Storage calls; `table` is then `storage.objects` and `filters`/`payload` stay empty. */
  storage?: StorageAccess;
  /** An earlier read of the same row by the same id value (see QueryGuard). */
  guard?: QueryGuard;
  /** Comparisons of this read's own row against other values in code, each stopping the entry point (see QueryGuard.checks). */
  ownerChecks?: QueryFilter[];
}

/** `// auditai:ignore <ruleId|*> -- reason` placed above a handler (or at the top of a file). */
export interface IgnoreDirective {
  ruleId: string;
  reason: string;
  location: FileRef;
}

/** Route handler, server action, or a server-rendered page (a GET that reads data for its params). */
export type EntryKind = "route" | "server_action" | "page";

/** A `user.user_metadata.role`-style access; user_metadata is editable by the end user. */
export interface MetadataAccess {
  path: string;
  bucket: "user_metadata" | "app_metadata";
  /** The property read from the metadata object (`role` in `ctx.user.user_metadata?.role`). */
  field?: string;
  location: FileRef;
}

/**
 * How the caller was authenticated. `session`: a user identity (Supabase auth, an auth library's session,
 * an auth wrapper); `secret`: a request credential compared with a server secret (cron secret, admin
 * password, env API key, webhook signature), i.e. an operator or a machine, not a tenant user;
 * `credential`: a per-account credential looked up by its hash (API keys), which identifies an account.
 */
export type AuthCheckKind = "session" | "secret" | "credential";

export interface AuthCheck extends FileRef {
  /** Absent in models written before 12 September 2026; read it as `session`. */
  kind?: AuthCheckKind;
}

/**
 * A role or claim of the authenticated session deciding whether the request goes on (ADR-001):
 * `if (!user || !isAdminEmail(user.email)) return 401`, `if (user.app_metadata?.role !== "admin")
 * redirect(...)`. The value comes from the session (`auth.getUser()`, an auth helper), never from
 * `user_metadata` (end-user editable, see R5) and never from the request.
 */
export interface RoleCheck extends FileRef {
  /** The session value the predicate reads, e.g. `user.email` or `user.app_metadata.role`. */
  source: string;
  /** The condition, for evidence. */
  text: string;
}

export interface RouteHandler {
  kind: EntryKind;
  /** Route path for routes and pages, function name for server actions. */
  route: string;
  method: HttpMethod | "ACTION" | "PAGE";
  /** Human-readable entry label, e.g. `GET /api/invoices/[id]`, `PAGE /invoices/[id]` or `server action deleteInvoice`. */
  entry: string;
  location: FileRef;
  inputs: InputSource[];
  authChecks: AuthCheck[];
  queries: SupabaseQuery[];
  metadataAccesses: MetadataAccess[];
  ignores: IgnoreDirective[];
  /** Role/claim predicates that stop the entry point (see RoleCheck). Absent in older models. */
  roleChecks?: RoleCheck[];
}

export type PolicyCommand = "select" | "insert" | "update" | "delete" | "all";

export interface PolicyDetail {
  name: string;
  command: PolicyCommand;
  roles: string[];
  using: string | null;
  check: string | null;
  location: FileRef;
}

/**
 * One column of a table, as the migrations leave it (CREATE TABLE plus later ALTER TABLE statements).
 * Enough to seed rows automatically: what to fill, with which type, and which parent row it needs.
 */
export interface ColumnInfo {
  /** Lowercase name, identical to the entry at the same index of `RlsTable.columns`. */
  name: string;
  /**
   * Lowercase canonical type with its modifiers and one `[]` per array dimension: `uuid`, `text`,
   * `varchar(80)`, `numeric(10,2)`, `integer`, `bigint`, `boolean`, `timestamptz`, `timestamp(3)`,
   * `jsonb`, `text[]`. Aliases are canonicalized (`character varying` -> `varchar`, `int4` -> `integer`,
   * `timestamp with time zone` -> `timestamptz`, `serial` -> `integer`). User-defined types (enums)
   * appear by bare lowercase name without schema, matching the keys of `ProjectModel.enums`.
   * `unknown` when the definition carries no type.
   */
  type: string;
  /** False for NOT NULL, PRIMARY KEY, serial and identity columns. */
  nullable: boolean;
  /** True when an insert may omit the column: DEFAULT <non-null expression>, serial, identity, GENERATED ... STORED. */
  hasDefault: boolean;
  /** Foreign-key target. Public tables by bare lowercase name, other schemas qualified (`auth.users`). */
  references: { table: string; column: string } | null;
  /** Identifier exactly as Postgres stores it, present only when it differs from `name` (quoted mixed case, e.g. Prisma's `"tenantId"`). */
  sqlName?: string;
}

/** A SQL function defined by the migrations, for judging what `supabase.rpc()` can reach. */
export interface SqlFunctionInfo {
  /** Lowercase name; the `public` schema is stripped, other schemas stay qualified (`private.fn`). Overloads share one entry. */
  name: string;
  securityDefiner: boolean;
  /**
   * The body, or a migration function it calls, reads the caller's identity: `auth.uid()`, `auth.jwt()`,
   * `auth.email()` or `current_setting('request.jwt...')`. `auth.role()` alone is not a caller check.
   */
  checksCaller: boolean;
  /** Roles that can execute it after all GRANT/REVOKE statements (see `sql-functions.ts` for the Supabase defaults assumed). */
  grantedTo: string[];
  location: FileRef;
  /** Lowercase return type (`uuid`, `setof invoices`, `table`, `void`, `trigger`). Trigger functions cannot be called through PostgREST. */
  returns?: string;
}

/** A Supabase Storage bucket created by migration SQL (`insert into storage.buckets ...`). */
export interface StorageBucket {
  id: string;
  /** Public buckets serve every object without authorization. False unless the SQL sets a literal true. */
  public: boolean;
  location: FileRef;
}

export interface RlsTable {
  /** Table key: bare lowercase name in schema public, `schema.table` elsewhere (`storage.objects`). */
  table: string;
  rlsEnabled: boolean;
  /** Policy names, kept for quick counts. */
  policies: string[];
  policyDetails: PolicyDetail[];
  columns: string[];
  /** Column details, index-aligned with `columns`. Present for tables parsed from migration SQL. */
  columnInfo?: ColumnInfo[];
  /** Table name exactly as Postgres stores it, present only when it differs from `table` (quoted mixed case, e.g. Prisma's `"Invoice"`). */
  sqlName?: string;
  location: FileRef;
}

export type ExposureKind = "service_role_in_client_component" | "public_env_service_role";

/** A secret that reaches the browser bundle. */
export interface SecretExposure {
  kind: ExposureKind;
  location: FileRef;
  evidence: string;
}

export interface ProjectModel {
  root: string;
  files: string[];
  routes: RouteHandler[];
  clientFactories: ClientFactory[];
  authHelpers: AuthHelper[];
  tables: RlsTable[];
  exposures: SecretExposure[];
  /** File-level ignore directives (comment before the first statement), keyed by file. */
  fileIgnores: Record<string, IgnoreDirective[]>;
  warnings: string[];
  /** Enum types from migration SQL: bare lowercase type name -> labels in declaration order. */
  enums?: Record<string, string[]>;
  /** Functions from migration SQL, in definition order. */
  sqlFunctions?: SqlFunctionInfo[];
  /** Storage buckets created by migration SQL, in creation order. */
  storageBuckets?: StorageBucket[];
}
