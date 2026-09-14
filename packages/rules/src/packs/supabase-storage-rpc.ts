import type { Evidence, Finding, Severity } from "@auditai/core";
import type { ClientNodeData, GraphNode, HandlerNodeData, QueryNodeData } from "@auditai/graph";
import type {
  FileRef,
  InputSource,
  PolicyDetail,
  StorageAccess,
  StorageBucket,
} from "@auditai/parser";
import type { Rule, RuleContext } from "../rule.js";
import { sqlFunctionsOf, storageBucketsOf } from "./sql-functions.js";
import { bypassesRls, policyScopesToCaller } from "./supabase-authorization.js";

// ---------------------------------------------------------------------------------------------
// Graph views shared by the three rules.

interface Reach {
  handler: GraphNode;
  handlerData: HandlerNodeData;
  inputs: InputSource[];
  authenticated: boolean;
  query: GraphNode;
  data: QueryNodeData;
  client: GraphNode | undefined;
  clientData: ClientNodeData | undefined;
}

/** Every (handler, query) pair of the graph, with the client the query runs as. */
function reaches(ctx: RuleContext): Reach[] {
  const out: Reach[] = [];
  for (const handler of ctx.graph.nodesOfKind("Handler")) {
    const handlerData = handler.data as unknown as HandlerNodeData;
    const authenticated = ctx.graph.out(handler.id, "AUTHENTICATED_BY").length > 0;
    for (const query of ctx.graph.out(handler.id, "CALLS")) {
      const client = ctx.graph.out(query.id, "USES_CLIENT")[0];
      out.push({
        handler,
        handlerData,
        inputs: (handlerData.inputs as InputSource[] | undefined) ?? [],
        authenticated,
        query,
        data: query.data as unknown as QueryNodeData,
        client,
        clientData: client?.data as ClientNodeData | undefined,
      });
    }
  }
  return out;
}

function locations(...refs: Array<FileRef | undefined>): FileRef[] {
  const out: FileRef[] = [];
  for (const r of refs) {
    if (r && !out.some((o) => o.file === r.file && o.line === r.line)) out.push(r);
  }
  return out;
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}

type FindingBody = Omit<
  Finding,
  "id" | "ruleId" | "status" | "severity" | "confidence" | "cwe" | "createdAt" | "updatedAt"
>;

function finding(ctx: RuleContext, rule: Rule, body: FindingBody, severity?: Severity): Finding {
  return {
    id: ctx.nextId(),
    ruleId: rule.id,
    status: "likely",
    severity: severity ?? rule.severity,
    confidence: rule.confidence,
    cwe: rule.cwe,
    createdAt: ctx.now,
    updatedAt: ctx.now,
    ...body,
  };
}

function bucketLabel(bucket: string | null): string {
  return bucket === null ? "a bucket chosen at runtime" : `bucket "${bucket}"`;
}

const OP_VERB: Readonly<Record<string, string>> = {
  download: "read",
  list: "list",
  createSignedUrl: "hand out links to",
  createSignedUrls: "hand out links to",
  upload: "write",
  createSignedUploadUrl: "write",
  copy: "copy",
  update: "overwrite",
  move: "move",
  remove: "delete",
};

// ---------------------------------------------------------------------------------------------

/**
 * S1. A Storage object is read or written through a client that skips storage policies (service role),
 * on a path the caller supplies and that is never tied to the caller's own id. The storage twin of R1.
 * Unauthenticated handlers are left to `supabase.service-role-query-without-authentication`: with no
 * session there is no caller to scope the path to, and one root cause gets one finding.
 */
export const storageObjectAccessWithoutOwnerScope: Rule = {
  id: "supabase.storage-object-access-without-owner-scope",
  title: "Storage object access via service-role client without owner scope",
  description:
    "A Supabase Storage download, upload, signed URL, move, copy, remove or list runs with the service-role key on a path the caller supplies. The service role skips storage policies and the path is never prefixed with or checked against the caller's user id, so any signed-in user can reach other users' files.",
  severity: "critical",
  confidence: 0.8,
  cwe: ["CWE-639", "CWE-284"],
  evaluate(ctx) {
    const out: Finding[] = [];
    for (const r of reaches(ctx)) {
      const s: StorageAccess | undefined = r.data.storage;
      if (!s || !bypassesRls(r.clientData?.kind)) continue;
      if (!s.pathInputDerived || s.pathScopedToCaller || !r.authenticated) continue;
      const verb = OP_VERB[s.op] ?? "access";
      const bucket = s.bucket ?? "(dynamic)";
      const client = r.clientData?.name ?? "client";
      const path = [
        r.handlerData.kind === "server_action" ? "Server action call" : "HTTP request",
        r.handlerData.entry,
        `${s.pathText} (user-controlled object path)`,
        `${client} (service role, bypasses storage policies)`,
        `storage.objects ${s.op} in ${bucketLabel(s.bucket)}`,
      ];
      const via =
        r.data.via && r.data.via.length > 0 ? ` Reached through ${r.data.via.join(" -> ")}.` : "";
      const evidence: Evidence[] = [
        {
          kind: "rule",
          summary: `storage.from(${s.bucket === null ? "…" : `"${s.bucket}"`}).${s.op}(${s.pathText}) runs through ${client}, a service-role client, so storage policies on storage.objects do not apply. The object path comes from the request and is neither prefixed with nor checked against the caller's user id, so any signed-in user can ${verb} any object in ${bucketLabel(s.bucket)}, including other users' files. The handler authenticates the caller but never ties the path to them.${via}`,
          locations: locations(r.handler.location, r.query.location, r.client?.location),
          data: {
            deterministic: false,
            ruleId: this.id,
            authenticated: r.authenticated,
            bucket,
            op: s.op,
            query: r.data.text,
          },
        },
        { kind: "trace", summary: path.join(" -> ") },
      ];
      out.push(
        finding(ctx, this, {
          title: `Cross-user storage ${s.op} in ${bucketLabel(s.bucket)} via service-role client`,
          entrypoints: [r.handlerData.entry],
          sources: r.inputs.map((i) => `${i.kind}:${i.name}`),
          sinks: [`supabase.storage.${s.op}:${bucket}`],
          path,
          evidence,
        }),
      );
    }
    return out;
  },
};

// ---------------------------------------------------------------------------------------------

/** The RLS parser keys tables outside the public schema qualified: storage policies live on "storage.objects". */
const STORAGE_OBJECTS = "storage.objects";

/** An owner or membership check: auth.uid(), a JWT claim, the owner/owner_id column, tenant helpers. */
function hasOwnerCheck(expr: string): boolean {
  return policyScopesToCaller(expr) || /\bowner\b/i.test(expr);
}

function stripStrings(expr: string): string {
  return expr.replace(/'(?:[^']|'')*'/g, "''");
}

/** The policy constrains the object path (folder, file name, extension) in some way we cannot judge. */
function constrainsPath(expr: string): boolean {
  return /\bstorage\s*\.\s*(foldername|filename|extension)\s*\(|\bname\b|\bpath_tokens\b/i.test(
    stripStrings(expr),
  );
}

export function bucketsIn(expr: string): string[] {
  const out: string[] = [];
  for (const m of expr.matchAll(/\bbucket_id\s*=\s*'([^']+)'/gi)) if (m[1]) out.push(m[1]);
  for (const m of expr.matchAll(/\bbucket_id\s+in\s*\(([^)]*)\)/gi)) {
    for (const v of (m[1] ?? "").matchAll(/'([^']+)'/g)) if (v[1]) out.push(v[1]);
  }
  return unique(out);
}

/** The expression that decides access for the command: USING for reads/changes, WITH CHECK for inserts. */
function decidingExpr(p: PolicyDetail): { expr: string; clause: "using" | "with check" } {
  if (p.command === "insert") return { expr: p.check ?? "true", clause: "with check" };
  if (p.using !== null) return { expr: p.using, clause: "using" };
  return { expr: p.check ?? "true", clause: "with check" };
}

const EVERYONE = new Set(["anon", "public"]);

/**
 * SELECT on a public bucket is by design (its objects are world-readable by URL anyway), and a SELECT
 * for anon/public on a bucket not declared private reads as an intentional public read.
 */
function intentionalPublicRead(
  p: PolicyDetail,
  buckets: string[],
  declared: ReadonlyMap<string, StorageBucket>,
): boolean {
  if (p.command !== "select") return false;
  const targeted =
    buckets.length > 0 ? buckets.map((b) => declared.get(b)) : [...declared.values()];
  if (targeted.length > 0 && targeted.every((b) => b?.public === true)) return true;
  return opensToEveryone(p) && !targeted.some((b) => b?.public === false);
}

/** No TO clause (PUBLIC) or a role list that includes anon/public: anonymous visitors qualify. */
function opensToEveryone(p: PolicyDetail): boolean {
  return p.roles.length === 0 || p.roles.some((r) => EVERYONE.has(r));
}

const COMMAND_VERB: Readonly<Record<string, string>> = {
  select: "read",
  insert: "upload into",
  update: "overwrite",
  delete: "delete",
  all: "read, overwrite and delete",
};

const COMMAND_OPS: Readonly<Record<string, readonly string[]>> = {
  select: ["download", "list", "createSignedUrl", "createSignedUrls"],
  insert: ["upload", "createSignedUploadUrl", "copy"],
  update: ["update", "move", "upload"],
  delete: ["remove", "move"],
};

/**
 * S2. A policy on storage.objects only checks which bucket the object is in. Every user the policy
 * applies to can then read, overwrite or delete every object of the bucket through the Storage API with
 * their own session, no route of ours involved. One finding per policy.
 */
export const storagePolicyWithoutOwnerCheck: Rule = {
  id: "supabase.storage-policy-without-owner-check",
  title: "Storage policy without an owner check",
  description:
    "A policy on storage.objects only checks bucket_id: no auth.uid(), no storage.foldername(name) ownership, no owner column. Every user it applies to can read, overwrite or delete every file in that bucket, not only their own.",
  severity: "high",
  confidence: 0.8,
  cwe: ["CWE-863", "CWE-284"],
  evaluate(ctx) {
    const declared = new Map(storageBucketsOf(ctx.model).map((b) => [b.id, b]));
    const storageReaches = reaches(ctx).filter(
      (r) =>
        r.data.storage !== undefined &&
        (r.clientData?.kind === "anon" || r.clientData?.kind === "user_scoped"),
    );
    const out: Finding[] = [];
    for (const t of ctx.model.tables) {
      if (t.table.toLowerCase() !== STORAGE_OBJECTS) continue;
      for (const p of t.policyDetails) {
        const { expr, clause } = decidingExpr(p);
        const buckets = bucketsIn(expr);
        if (hasOwnerCheck(expr) || constrainsPath(expr)) continue;
        if (intentionalPublicRead(p, buckets, declared)) continue;
        const ops = COMMAND_OPS[p.command];
        const reached = storageReaches.filter((r) => {
          const s = r.data.storage;
          if (!s) return false;
          if (buckets.length > 0 && (s.bucket === null || !buckets.includes(s.bucket)))
            return false;
          return ops === undefined || ops.includes(s.op);
        });
        const everyone = opensToEveryone(p);
        const who = everyone ? "anyone" : `any ${p.roles.join("/")} user`;
        const whoLong = everyone ? "anyone, signed in or not," : who;
        const where = buckets.length > 0 ? buckets.map((b) => `"${b}"`).join(", ") : "every bucket";
        const privateNote = buckets
          .map((b) => declared.get(b))
          .filter((b): b is StorageBucket => b !== undefined && !b.public)
          .map(
            (b) => ` Bucket "${b.id}" is declared private (${b.location.file}:${b.location.line}).`,
          )
          .join("");
        const entries = unique(reached.map((r) => r.handlerData.entry));
        const storageEntry = `Storage API: ${buckets.length > 0 ? `bucket ${where}` : "all buckets"}`;
        const verb = COMMAND_VERB[p.command] ?? "access";
        const path = [
          entries[0] ?? storageEntry,
          everyone ? "anyone, with the anon key or a session" : `${who} with their own session`,
          `storage.objects policy "${p.name}" ${clause} (${expr})`,
          `every object in ${where}`,
        ];
        const reachNote =
          entries.length > 0
            ? ` The app reaches the bucket from ${entries.join(", ")} with a client that relies on this policy.`
            : "";
        // An INSERT policy adds files; reading, replacing and deleting the ones already there take others.
        const insertOnly = p.command === "insert";
        const insertNote = insertOnly
          ? " An INSERT policy cannot read, replace or delete existing files, so this is reported as medium: what it allows is placing files in other users' folders."
          : "";
        out.push(
          finding(
            ctx,
            this,
            {
              title: `Storage policy "${p.name}" lets ${who} ${verb} every object in ${buckets.length > 0 ? `bucket ${where}` : "every bucket"}`,
              entrypoints: [...entries, storageEntry],
              sources: unique([
                ...reached.flatMap((r) => r.inputs.map((i) => `${i.kind}:${i.name}`)),
                "storage API (caller's own session)",
              ]),
              sinks:
                buckets.length > 0
                  ? buckets.map((b) => `storage.objects:${b}`)
                  : ["storage.objects"],
              path,
              evidence: [
                {
                  kind: "rule",
                  summary: `Policy "${p.name}" for ${p.command} on storage.objects ${clause} (${expr}) checks only the bucket: no auth.uid(), no storage.foldername(name) ownership, no owner column. So ${whoLong} can ${verb} every object in ${where}, including other users' files, straight through the Storage API.${privateNote}${reachNote}${insertNote} Scope it to the owner, e.g. bucket_id = '${buckets[0] ?? "<bucket>"}' and (storage.foldername(name))[1] = (select auth.uid())::text.`,
                  locations: locations(p.location, ...reached.map((r) => r.query.location)),
                  data: { deterministic: false, ruleId: this.id, policy: p.name, buckets },
                },
                { kind: "trace", summary: path.join(" -> ") },
              ],
            },
            insertOnly ? "medium" : undefined,
          ),
        );
      }
    }
    return out;
  },
};

// ---------------------------------------------------------------------------------------------

/** `true`, with any parentheses: a policy predicate that lets every row through. */
const EVERY_ROW = /^\(*\s*true\s*\)*$/i;
/** A file the Supabase CLI applies: directly inside `supabase/migrations/`. */
const MIGRATION_SQL = /(?:^|\/)supabase\/migrations\/[^/]+\.sql$/i;

/**
 * A definer function that can hand out nothing RLS does not already show to anyone: it writes
 * nothing, calls no other migration function, and every table it reads has RLS on and a SELECT (or
 * ALL) policy for anonymous visitors that lets every row through. Tables the schema does not know
 * (views, CTE names, auth.users) keep the finding. Column-level grants are not modelled. Silencing
 * takes stronger evidence than reporting: with `fromMigrationsOnly`, only a policy a Supabase migration
 * declares counts, because hand-run SQL beside the migrations (`database/RLS_FIX.sql`) may never
 * have reached the database.
 */
function readsOnlyPublicRows(
  fn: { tables?: string[]; writes?: string[]; calls?: string[] },
  tables: ReadonlyMap<string, { rlsEnabled: boolean; policyDetails: readonly PolicyDetail[] }>,
  fromMigrationsOnly: boolean,
): boolean {
  if ((fn.writes?.length ?? 0) > 0 || (fn.calls?.length ?? 0) > 0) return false;
  const read = fn.tables ?? [];
  return (
    read.length > 0 &&
    read.every((name) => {
      const t = tables.get(name);
      return (
        t?.rlsEnabled === true &&
        t.policyDetails.some(
          (p) =>
            (p.command === "select" || p.command === "all") &&
            opensToEveryone(p) &&
            p.using !== null &&
            EVERY_ROW.test(p.using.trim()) &&
            (!fromMigrationsOnly || MIGRATION_SQL.test(p.location.file)),
        )
      );
    })
  );
}

/** Roles PostgREST requests run as. */
const API_ROLES = new Set(["anon", "authenticated", "public"]);

interface FunctionFacts {
  name: string;
  returns?: string;
  args?: string;
  params?: Array<{ name: string }>;
  tables?: string[];
  writes?: string[];
  calls?: string[];
}

/** A parameter that names a person: a yes/no about someone the caller picks reveals their memberships or roles. */
const NAMES_A_PERSON =
  /(^|_)(user|uid|profile|member|person|owner|customer|employee|student|patient|email)(_?id)?$/i;
/** A parameter that carries a credential: a yes/no answer about it is a guessing oracle. */
const CARRIES_CREDENTIAL = /(^|_)(pin|password|passwd|secret|token|otp|code|hash)$/i;

/** The system catalog describes the schema itself (`information_schema.columns`, `pg_constraint`), not anyone's rows. */
function isCatalogRelation(name: string): boolean {
  return (
    name.startsWith("information_schema.") ||
    name.startsWith("pg_catalog.") ||
    /^pg_[a-z_]+$/.test(name)
  );
}

/** Neither the function nor any migration function it calls writes a table. A callee the migrations do not define counts as writing. */
function writesNothing(
  fn: FunctionFacts,
  byName: ReadonlyMap<string, FunctionFacts>,
  seen: Set<string> = new Set(),
): boolean {
  if ((fn.writes?.length ?? 0) > 0) return false;
  if (seen.has(fn.name)) return true;
  seen.add(fn.name);
  return (fn.calls ?? []).every((c) => {
    const callee = byName.get(c);
    return callee !== undefined && writesNothing(callee, byName, seen);
  });
}

/**
 * What a definer function that changes nothing can hand out: only true or false, or only rows of the
 * system catalog. Null when it may return other users' rows or has effects. A function that returns
 * nothing while reading the catalog is doing something else (DDL), so it keeps its severity. So does a
 * yes/no answer about a person the caller names (`is_tribe_admin(p_tribe_id, p_user_id)` reveals a
 * membership RLS hides) or about a credential (`verify_staff_pin(p_pin)` can be guessed against).
 */
function narrowResult(
  fn: FunctionFacts,
  byName: ReadonlyMap<string, FunctionFacts>,
): "boolean" | "catalog" | null {
  if (!writesNothing(fn, byName)) return null;
  if (fn.returns === "boolean") {
    // Unread parameters prove nothing about whom the answer is about.
    if (fn.params === undefined && fn.args !== "") return null;
    const about = (fn.params ?? []).map((p) => p.name);
    return about.some((n) => NAMES_A_PERSON.test(n) || CARRIES_CREDENTIAL.test(n))
      ? null
      : "boolean";
  }
  const read = fn.tables ?? [];
  if (fn.returns !== "void" && read.length > 0 && read.every(isCatalogRelation)) return "catalog";
  return null;
}

/**
 * S3. A SECURITY DEFINER function runs with its owner's rights, so RLS does not apply inside it. When
 * its body never reads the caller's identity, every role that may EXECUTE it gets whatever it returns
 * or changes, through `supabase.rpc()` or POST /rest/v1/rpc/<fn>. Critical when anon or PUBLIC can
 * execute it (Supabase's default for public functions), high when only signed-in users can.
 */
export const securityDefinerFunctionWithoutCallerCheck: Rule = {
  id: "supabase.security-definer-function-without-caller-check",
  title: "SECURITY DEFINER function without a caller check",
  description:
    "A public-schema SECURITY DEFINER function runs with its owner's rights and skips Row Level Security, and its body never reads auth.uid() or auth.jwt(). Anyone allowed to call it through supabase.rpc() gets other users' rows or actions.",
  severity: "high",
  confidence: 0.75,
  cwe: ["CWE-862", "CWE-250"],
  evaluate(ctx) {
    const fns = sqlFunctionsOf(ctx.model);
    const rpcByName = new Map<string, Reach[]>();
    for (const r of reaches(ctx)) {
      if (r.data.operation !== "rpc") continue;
      const key = r.data.table.toLowerCase();
      rpcByName.set(key, [...(rpcByName.get(key) ?? []), r]);
    }
    const tables = new Map(ctx.model.tables.map((t) => [t.table, t]));
    const hasMigrations = ctx.model.files.some((f) => MIGRATION_SQL.test(f));
    const byName = new Map(fns.map((f) => [f.name, f]));
    const out: Finding[] = [];
    for (const fn of fns) {
      if (!fn.securityDefiner || fn.checksCaller) continue;
      // Other schemas are not exposed through PostgREST by default; trigger functions cannot be called.
      if (fn.name.includes(".")) continue;
      if (fn.returns === "trigger" || fn.returns === "event_trigger") continue;
      const roles = fn.grantedTo.filter((r) => API_ROLES.has(r));
      if (roles.length === 0) continue;
      // Nothing to hand out: every row it can read is already public through RLS.
      if (readsOnlyPublicRows(fn, tables, hasMigrations)) continue;
      // A yes/no answer or the schema's own catalog is not other users' rows: lowered, never dropped,
      // because a boolean can still confirm that a record exists or that a user holds a role.
      const narrow = narrowResult(fn, byName);
      const narrowNote =
        narrow === "boolean"
          ? " It changes nothing and returns only true or false, so it is reported as medium: a yes/no answer about ids the caller supplies can still confirm that a record exists or that a user holds a role."
          : narrow === "catalog"
            ? " It changes nothing and reads only the system catalog, so it is reported as medium: it describes the schema, not anyone's rows."
            : "";
      const anonymous = roles.includes("anon") || roles.includes("public");
      const sites = rpcByName.get(fn.name) ?? [];
      const entries = unique(sites.map((s) => s.handlerData.entry));
      const endpoint = `POST /rest/v1/rpc/${fn.name}`;
      const who = anonymous
        ? "Anonymous visitors can call it with the public anon key"
        : "Any signed-in user can call it";
      const callNote =
        entries.length > 0
          ? ` The app calls it with supabase.rpc("${fn.name}") from ${entries.join(", ")}.`
          : "";
      const path = [
        entries[0] ?? endpoint,
        `supabase.rpc("${fn.name}") (EXECUTE: ${roles.join(", ")})`,
        `public.${fn.name}() SECURITY DEFINER (runs as its owner, RLS does not apply)`,
        "no auth.uid() / auth.jwt() check",
      ];
      out.push(
        finding(
          ctx,
          this,
          {
            title: `${anonymous ? "Anonymous-callable " : ""}SECURITY DEFINER function "${fn.name}" without a caller check`,
            entrypoints: [...entries, endpoint],
            sources: unique([
              ...sites.flatMap((s) => s.inputs.map((i) => `${i.kind}:${i.name}`)),
              "rpc arguments",
            ]),
            sinks: [`postgres.function:public.${fn.name}`],
            path,
            evidence: [
              {
                kind: "rule",
                summary: `public.${fn.name}() is SECURITY DEFINER: it runs with the rights of its owner and Row Level Security does not apply inside it. Its body never reads the caller's identity (auth.uid(), auth.jwt(), auth.email() or the request JWT), so whatever it returns or changes is available to every role that can execute it: ${roles.join(", ")}. ${who} at ${endpoint}.${callNote}${narrowNote} Filter by auth.uid() inside the function, make it SECURITY INVOKER, or revoke EXECUTE from public, anon and authenticated.`,
                locations: locations(
                  fn.location,
                  ...sites.flatMap((s) => [s.handler.location, s.query.location]),
                ),
                data: {
                  deterministic: false,
                  ruleId: this.id,
                  function: fn.name,
                  grantedTo: [...fn.grantedTo],
                  ...(narrow ? { narrowResult: narrow } : {}),
                },
              },
              { kind: "trace", summary: path.join(" -> ") },
            ],
          },
          narrow ? "medium" : anonymous ? "critical" : "high",
        ),
      );
    }
    return out;
  },
};

export const supabaseStorageRpcPack: readonly Rule[] = [
  storageObjectAccessWithoutOwnerScope,
  storagePolicyWithoutOwnerCheck,
  securityDefinerFunctionWithoutCallerCheck,
];
