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
  location: FileRef;
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
  authChecks: FileRef[];
  queries: SupabaseQuery[];
  metadataAccesses: MetadataAccess[];
  ignores: IgnoreDirective[];
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

export interface RlsTable {
  table: string;
  rlsEnabled: boolean;
  /** Policy names, kept for quick counts. */
  policies: string[];
  policyDetails: PolicyDetail[];
  columns: string[];
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
}
