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
  /**
   * The value is the caller's identity, or read off a row that identity selected: `user.id`, `dev.id`
   * where `dev` was selected by `claimed_by = user.id`, the account a session token looked up. Absent
   * otherwise. When a value is also `inputDerived`, the input wins.
   */
  identity?: boolean;
  /**
   * For a comparison made by a helper: the caller's role test that lets the caller through without
   * the comparison (`user.role === "admin"` in `canAccessRequest`). Absent when every path compares.
   */
  bypass?: string;
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
  /**
   * True when every user-controlled path argument is a key minted in this request: its last segment
   * carries a random token the handler generated (`${folder}/${crypto.randomUUID()}.jpg`), nothing
   * after the token can open a new segment and nothing the caller sends before it can end the URL
   * path. Such a key names an object that did not exist before the request.
   */
  pathServerMinted?: boolean;
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
  /**
   * Which Supabase call established a `session` check, when it was a direct one. It matters because
   * the three are not equivalent on the server: `getUser` asks the Auth server and `getClaims`
   * verifies the token's signature, while `getSession` only reads the session out of the cookie
   * without revalidating it, so its claims are whatever the browser put there. Absent for auth
   * helpers whose body is analysed separately, and in models written before 19 September 2026.
   */
  method?: "getUser" | "getSession" | "getClaims";
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
  /**
   * Set when the role is a column of a row the caller's identity selected (`profil.rolle` read from
   * `profiles` by `id = user.id`): who can write that column decides whether the gate holds.
   */
  table?: string;
  column?: string;
}

/**
 * A call to the Supabase Auth admin API (`auth.admin.deleteUser`, `updateUserById`, `getUserById`,
 * ...). It only works with the service-role key and it acts on accounts rather than on rows, so no
 * policy constrains it: whatever user id it is handed is the account it touches.
 */
export interface AdminApiCall extends FileRef {
  /** The method after `auth.admin.`, e.g. `deleteUser`. */
  method: string;
  /** The first argument as written, for evidence. */
  argText: string;
  /** True when that argument is derived from a user-controlled input of the handler. */
  inputDerived: boolean;
  /** True when it is the caller's own identity (`user.id`), which is the legitimate shape. */
  identity: boolean;
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
  /** Calls to the Auth admin API. Absent in models written before 19 September 2026. */
  adminApiCalls?: AdminApiCall[];
  /**
   * The handler returns (or throws) first thing when NODE_ENV is "production", the value Next.js
   * inlines into every production build: a development-only route. Computed only for entry points
   * that authenticate nothing themselves.
   */
  productionExit?: FileRef;
}

export type PolicyCommand = "select" | "insert" | "update" | "delete" | "all";

export interface PolicyDetail {
  name: string;
  command: PolicyCommand;
  roles: string[];
  using: string | null;
  check: string | null;
  location: FileRef;
  /**
   * False for `AS RESTRICTIVE`: such a policy can only narrow what the permissive ones allow, so by
   * itself it opens nothing. Absent means permissive, the Postgres default.
   */
  permissive?: false;
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
  /**
   * Argument types as written, comma separated (`uuid, integer`), empty string for none. Postgres
   * identifies a function by name and argument types, so GRANT and REVOKE need them. Absent when
   * the parameter list could not be read; overloads share one entry, and this is the first one seen.
   */
  args?: string;
  /**
   * The argument list exactly as Postgres identifies the function (`p_status "OrderStatus"`,
   * `character varying, integer`), from a live snapshot. A fix names the function with it verbatim;
   * `args` is lowercased and simplified and can name a type that does not exist.
   */
  identity?: string;
  /** The function name exactly as Postgres stores it, when it differs from `name` (quoted mixed case). */
  sqlName?: string;
  /**
   * Input parameters with their names, in order: what an rpc call body is keyed by. Absent when any
   * input parameter is unnamed or the list could not be read.
   */
  params?: Array<{ name: string; type: string; default?: true }>;
  /**
   * Relations named after FROM or JOIN in the body (lowercase, `public.` stripped): the tables it can
   * read, or delete from. Unfiltered text matches; keep only names the schema has.
   */
  tables?: string[];
  /** Tables the body writes (`update t`, `insert into t`, `delete from t`); same caveats as `tables`. */
  writes?: string[];
  /**
   * Tables the body can change existing rows of: `update t`, `delete from t`, `merge into t`,
   * `truncate t` (which RLS does not see at all, and Supabase grants to the API roles), and
   * `*` when it runs dynamic SQL (EXECUTE) next to one of those words, so any table may be meant.
   * A SECURITY INVOKER function that writes without reading a column (`where true`, a BEGIN ATOMIC
   * body, MERGE) is not stopped by safeupdate, and no SELECT policy limits it. From a live snapshot
   * only for functions that are not SECURITY DEFINER; same text-match caveats as `tables`.
   */
  changes?: string[];
  /**
   * Parameters compared with a column in a WHERE/ON/AND/OR/IF clause of the body: `where i.id =
   * p_invoice_id` gives `{ param: "p_invoice_id", table: "invoices", column: "id" }`.
   */
  keys?: Array<{ param: string; table: string; column: string }>;
  /** Migration functions the body calls, spelled like `name`; absent when it calls none. */
  calls?: string[];
  /**
   * Text parameters that reach the statement text of an EXECUTE unquoted (`'...' || p`, `format('%s',
   * p)`, `execute p`), directly or through a local variable: the caller writes part of the SQL the
   * function runs. Absent when none does. See `paramsReachingExecute` in `sql-dynamic.ts`; from a live
   * snapshot only for SECURITY DEFINER functions, whose bodies the query sends.
   */
  sqlFromParams?: string[];
}

/** A trigger from migration SQL, kept for what RLS cannot express: columns a row's owner may not change. */
export interface SqlTrigger {
  /** Lowercase trigger name. */
  name: string;
  /** Table key, like `RlsTable.table`. */
  table: string;
  timing: "before" | "after" | "instead of";
  events: Array<"insert" | "update" | "delete" | "truncate">;
  /**
   * Columns the trigger holds back on NEW: an `UPDATE OF` list, or columns its function reads off NEW
   * and also reads off OLD, assigns with `:=`, or reads in a body that raises.
   */
  checkedColumns: string[];
  /** The trigger function, keyed like `SqlFunctionInfo.name`. */
  function: string;
  location: FileRef;
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
  /**
   * What the relation is, when a live snapshot says so. Row level security exists only for tables;
   * a view or a materialized view never has it, and saying it is "off" there is wrong.
   */
  kind?: "table" | "partitioned" | "view" | "matview";
  /**
   * Views only: true when the view runs with the caller's rights (`with (security_invoker = on)`),
   * so the row level security of the tables under it applies; false when it runs with its owner's,
   * which on Supabase is postgres, and no policy applies. A materialized view is always false: it is
   * a stored copy. Absent for a table, and for a snapshot taken before the query read it.
   */
  viewSecurityInvoker?: boolean;
  /** Views only: the relations the definition selects from, as model keys (`invoices`, `auth.users`). */
  viewSources?: string[];
  /**
   * Table privileges the API roles hold, from a live snapshot (lowercase: select, insert, update,
   * delete; PUBLIC counted for both). Absent when the source does not say, which is every migration
   * scan: Supabase grants all four to both roles by default, and rules then assume that.
   */
  apiGrants?: { anon: string[]; authenticated: string[] };
  /**
   * Column privileges the API roles hold on some column of the table (`grant update (v) on t to
   * authenticated`), from a live snapshot; same shape as `apiGrants`. A PATCH that only sets those
   * columns goes through even without the table privilege.
   */
  apiColumnGrants?: { anon: string[]; authenticated: string[] };
  /**
   * A policy statement the parser does not evaluate names this table: CREATE, ALTER or DROP POLICY
   * inside a DO block (a conditional `if not exists ... create policy`), or ALTER POLICY. The policies
   * listed may then differ from the database's, so nothing may be concluded from a policy being
   * absent. Migration scans only; absent otherwise.
   */
  policiesUnread?: true;
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
  /** Triggers from migration SQL still in force; absent when there are none. */
  sqlTriggers?: SqlTrigger[];
  /**
   * The project's `middleware.ts` verifies the session before a handler runs: it calls
   * `auth.getUser()` or `auth.getClaims()`, or checks the token's signature itself against the
   * project's JWKS. Handlers it covers then read a token somebody has already checked, which is the
   * documented reason applications keep using `getSession()` on the server.
   *
   * `matcher` is the entries of the middleware's exported `config.matcher`, and it decides which
   * routes that protection reaches: an empty list means Next.js runs the middleware on everything.
   * Reading it is not optional — GoalSquad verifies in middleware but lists only page prefixes, so
   * its `/api` handlers get nothing, while klubb-app matches everything but a few static paths.
   * Absent when there is no middleware, or in models written before 19 September 2026.
   */
  middlewareVerifiesSession?: { matcher: string[] };
  /**
   * The Data API refuses UPDATE and DELETE without a WHERE clause: `authenticator`, the role PostgREST
   * logs in as, preloads safeupdate. Then every change through the API carries a filter that reads a
   * column, and Postgres applies the table's SELECT policies to the rows it changes too — a stranger
   * changes only rows they can read. Supabase has preloaded it on every project since January 2022
   * (supabase/postgres migration 20220118070449); the project owner can switch it off with `alter role
   * authenticator set safeupdate.enabled = off`. Read only from a live snapshot; absent means the
   * Supabase default.
   */
  dataApiRefusesUnfilteredWrites?: boolean;
  /**
   * Some DO block creates, alters or drops policies through dynamic SQL (`execute format('create
   * policy ... on %I', t)`), so any table's policies may differ from what the migrations show; see
   * `RlsTable.policiesUnread`. Migration scans only.
   */
  policiesUnread?: true;
  /**
   * The model was read off a live database (a snapshot), not rebuilt from files. Only then is a
   * policy's absence a fact: a migration scan does not see policies created in the dashboard, by a
   * function the migrations call, or in SQL it does not evaluate.
   */
  fromLiveDatabase?: true;
}
