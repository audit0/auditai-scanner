import type { Evidence, Finding, Severity } from "@auditai/core";
import type {
  FileRef,
  PolicyCommand,
  PolicyDetail,
  RlsTable,
  SqlFunctionInfo,
} from "@auditai/parser";
import type { Rule, RuleContext } from "../rule.js";

/**
 * Rules that read only the migrations. Unlike the authorization pack, they do not need a query from
 * the application: the defect is in the schema itself and PostgREST exposes it to anyone holding the
 * public anon key, whether or not this repository ever queries the table. The entry point is
 * therefore the Data API rather than a route, and the evidence always quotes the SQL that decides.
 *
 * Only tables in the `public` schema are considered: `storage.objects` and other Supabase-managed
 * tables have RLS enabled by the platform (not by a migration in this repository) and their policies
 * are the storage pack's subject.
 */

/** The entry point of every rule in this pack: the Data API, reachable with the public anon key. */
const DATA_API = "Supabase Data API (PostgREST)";

function locations(...refs: Array<FileRef | undefined>): FileRef[] {
  const out: FileRef[] = [];
  for (const r of refs) {
    if (r && !out.some((o) => o.file === r.file && o.line === r.line)) out.push(r);
  }
  return out;
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

/** Tables the migrations define in the `public` schema, in file order. */
function publicTables(ctx: RuleContext): RlsTable[] {
  return ctx.model.tables.filter((t) => !t.table.includes("."));
}

/** `for select`, `for all`, ... as it reads in a sentence. */
function commandLabel(p: PolicyDetail): string {
  return p.command === "all" ? "for all commands" : `for ${p.command}`;
}

/** Roles a policy applies to, spelled the way the SQL does. No TO clause means PUBLIC in Postgres. */
function roleLabel(p: PolicyDetail): string {
  return p.roles.length === 0 ? "public (no TO clause)" : p.roles.join(", ");
}

/** One short line of SQL for the evidence, collapsed and clipped. */
function quote(expr: string | null, max = 200): string {
  if (expr === null) return "(none)";
  const one = expr.replace(/\s+/g, " ").trim();
  return one.length > max ? `${one.slice(0, max - 1)}…` : one;
}

// ---------------------------------------------------------------------------------------------

const USER_METADATA = /\buser_metadata\b/i;
const RAW_USER_META = /\braw_user_meta_data\b/i;
const JWT_SOURCE = /auth\s*\.\s*jwt\s*\(|request\.jwt\.claim/i;
const AUTH_USERS = /\bauth\s*\.\s*users\b/i;

/**
 * Does this predicate decide from metadata the user writes themselves? `user_metadata` counts only
 * when it is read out of the token (`auth.jwt()`, `current_setting('request.jwt.claims')`), and
 * `raw_user_meta_data` only when it is read from `auth.users`: both names also occur as ordinary
 * columns on tables an application controls, and those are not self-granted.
 */
function readsSelfWrittenMetadata(expr: string): boolean {
  if (USER_METADATA.test(expr) && JWT_SOURCE.test(expr)) return true;
  return RAW_USER_META.test(expr) && AUTH_USERS.test(expr);
}

/**
 * A policy decides access from `user_metadata`, which the user owns: `updateUser({ data })` writes it
 * and it is signed into the next JWT without review. Supabase's own lint (0015) rates this an error.
 * Deterministic from SQL alone; the predicate is quoted in the evidence.
 */
export const rlsPolicyTrustsUserMetadata: Rule = {
  id: "supabase.rls-policy-trusts-user-metadata",
  title: "RLS policy reads user_metadata from the JWT",
  description:
    "A policy decides access with a claim under user_metadata (or raw_user_meta_data). Any signed-in user can write user_metadata with updateUser({ data }), and the claim lands in their next JWT without validation, so the policy grants itself. Move the claim to app_metadata, which only the service role writes, or read a roles table joined on auth.uid().",
  severity: "critical",
  confidence: 0.9,
  cwe: ["CWE-602", "CWE-863"],
  evaluate(ctx) {
    const out: Finding[] = [];
    for (const t of publicTables(ctx)) {
      for (const p of t.policyDetails) {
        const where: Array<[string, string]> = [];
        if (p.using !== null && readsSelfWrittenMetadata(p.using)) where.push(["USING", p.using]);
        if (p.check !== null && readsSelfWrittenMetadata(p.check))
          where.push(["WITH CHECK", p.check]);
        if (where.length === 0) continue;
        const clause = where.map(([kind, expr]) => `${kind} ${quote(expr)}`).join(" / ");
        const evidence: Evidence[] = [
          {
            kind: "rule",
            summary: `Policy "${p.name}" on public.${t.table} (${commandLabel(p)}, to ${roleLabel(p)}) decides access from user_metadata: ${clause}. A signed-in user sets user_metadata themselves with supabase.auth.updateUser({ data: { ... } }); the value is copied into their next access token without any check, so the caller can grant themselves whatever this predicate asks for. app_metadata cannot be written this way, and a roles table joined on auth.uid() cannot either.`,
            locations: locations(p.location, t.location),
            // No `deterministic: true`: a critical deterministic finding blocks the GitHub
            // check, and this rule has not been seen on a real repository yet (zero hits on the
            // 26-repository corpus of 13 Sept 2026). It blocks once measured, not before.
            data: {
              ruleId: this.id,
              table: t.table,
              policy: p.name,
              command: p.command,
            },
          },
          {
            kind: "trace",
            summary: [
              "Any signed-in user",
              'auth.updateUser({ data: { role: "admin" } })',
              "the claim is signed into the next JWT",
              `policy "${p.name}" reads it from user_metadata`,
              `public.${t.table} (${commandLabel(p)})`,
            ].join(" -> "),
          },
        ];
        out.push(
          finding(ctx, this, {
            title: `Policy "${p.name}" on "${t.table}" trusts user_metadata`,
            entrypoints: [DATA_API],
            sources: ["jwt:user_metadata"],
            sinks: [`supabase.policy:public.${t.table}`],
            path: [
              "Any signed-in user",
              "user_metadata written by the user",
              `policy "${p.name}"`,
              `public.${t.table}`,
            ],
            evidence,
          }),
        );
      }
    }
    return out;
  },
};

// ---------------------------------------------------------------------------------------------

/**
 * The migrations write policies for a table and never enable RLS, so none of them apply. Unlike
 * `table-without-rls`, this needs no query from the app: the policies themselves prove the table is
 * meant to be private, which is why the confidence is higher and the finding stands on SQL alone.
 */
export const policiesWithoutRlsEnabled: Rule = {
  id: "supabase.policies-without-rls-enabled",
  title: "Policies exist but RLS is never enabled on the table",
  description:
    "A migration writes policies for a table but never runs `alter table ... enable row level security`, so the policies have no effect and the table stays fully readable and writable through the Data API. Every reviewer who sees the policies assumes the table is protected. Supabase's own lint (0007) reports the same shape.",
  severity: "high",
  confidence: 0.9,
  cwe: ["CWE-284"],
  evaluate(ctx) {
    const out: Finding[] = [];
    for (const t of publicTables(ctx)) {
      if (t.rlsEnabled || t.policyDetails.length === 0 || isView(t)) continue;
      // No API role holds any privilege on it: the Data API refuses before RLS would matter.
      if (!apiReaches(t, [], PRIVILEGES.all)) continue;
      const names = t.policyDetails.map((p) => `"${p.name}" (${commandLabel(p)})`).join(", ");
      const evidence: Evidence[] = [
        {
          kind: "rule",
          summary: `public.${t.table} has ${t.policyDetails.length} ${t.policyDetails.length === 1 ? "policy" : "policies"} — ${names} — and no "alter table public.${t.table} enable row level security" anywhere in the migrations. Policies only apply to a table with RLS on, so every one of them is dead and the table is fully readable and writable by anyone holding the public anon key. The policies say what the intent was, which is what makes this a defect rather than a choice.`,
          locations: locations(t.location, t.policyDetails[0]?.location),
          data: {
            deterministic: true,
            ruleId: this.id,
            table: t.table,
            policies: t.policyDetails.map((p) => p.name),
          },
        },
        {
          kind: "trace",
          summary: [
            "Anyone with the public anon key",
            "PostgREST",
            `public.${t.table} (RLS never enabled)`,
            `${t.policyDetails.length} policies that never run`,
          ].join(" -> "),
        },
      ];
      out.push(
        finding(ctx, this, {
          title: `Table "${t.table}" has policies but RLS is off`,
          entrypoints: [DATA_API],
          sources: ["anon-key"],
          sinks: [`supabase.select:public.${t.table}`],
          path: [
            "Anyone with the public anon key",
            "PostgREST",
            `public.${t.table} (RLS off, policies inert)`,
          ],
          evidence,
        }),
      );
    }
    return out;
  },
};

// ---------------------------------------------------------------------------------------------

/** `true`, `(true)`, `((true))` — a predicate that decides nothing. */
export function isTautology(expr: string | null): boolean {
  if (expr === null) return false;
  // `true` as written, or a number compared with itself (`(1 = 1)`, the way pg_policies prints `1=1`).
  return /^\(*\s*(?:true|(\d+)\s*=\s*\1)\s*\)*$/i.test(expr.trim());
}

/** A RESTRICTIVE policy only narrows what the permissive ones allow: by itself it opens nothing. */
export function opensAccess(p: PolicyDetail): boolean {
  return p.permissive !== false;
}

const PRIVILEGES: Readonly<Record<PolicyCommand, readonly string[]>> = {
  select: ["select"],
  insert: ["insert"],
  update: ["update"],
  delete: ["delete"],
  all: ["select", "insert", "update", "delete"],
};

/**
 * Does one of the policy's roles hold a table privilege for one of these commands? Without it the
 * Data API refuses before any policy runs. Grants unknown (every migration scan) means the Supabase
 * default: anon and authenticated hold all four.
 */
export function apiReaches(
  t: RlsTable,
  roles: readonly string[],
  privileges: readonly string[],
): boolean {
  const g = t.apiGrants;
  if (!g) return true;
  const everyone = roles.length === 0 || roles.includes("public");
  const held = [
    ...(everyone || roles.includes("anon") ? g.anon : []),
    ...(everyone || roles.includes("authenticated") ? g.authenticated : []),
  ];
  return privileges.some((p) => held.includes(p));
}

/** The privileges a policy's command needs, writes only. */
export function writePrivileges(command: PolicyCommand): readonly string[] {
  return PRIVILEGES[command].filter((p) => p !== "select");
}

/** Row level security exists only for tables; a view or a materialized view never has it. */
export function isView(t: RlsTable): boolean {
  return t.kind === "view" || t.kind === "matview";
}

const ANON_ROLES = new Set(["anon", "public"]);

/** Does the policy apply to the anonymous role? No TO clause means PUBLIC, which includes anon. */
export function reachableByAnon(p: PolicyDetail): boolean {
  if (p.roles.length === 0) return true;
  return p.roles.some((r) => ANON_ROLES.has(r.toLowerCase().replace(/^"|"$/g, "")));
}

export const WRITE_COMMANDS: ReadonlySet<string> = new Set(["insert", "update", "delete", "all"]);

/** `false`, `(false)`: a predicate no row passes. */
export function isContradiction(expr: string | null): boolean {
  return expr !== null && /^\(*\s*false\s*\)*$/i.test(expr.trim());
}

/** The two roles a stranger reaches the Data API as: with the publishable key, or signed up. */
export type Stranger = "anon" | "authenticated";

/** Does the policy apply to this role? No TO clause and PUBLIC apply to every role. */
function appliesTo(p: PolicyDetail, role: Stranger): boolean {
  if (p.roles.length === 0) return true;
  return p.roles.some((r) => {
    const name = r.toLowerCase().replace(/^"|"$/g, "");
    return name === "public" || name === role;
  });
}

/**
 * Which rows a stranger changes through the Data API with an UPDATE, DELETE or ALL policy whose
 * USING is a tautology.
 *
 * Supabase preloads safeupdate for `authenticator`, the role PostgREST logs in as, so an UPDATE or
 * DELETE without WHERE is refused, and every PATCH and DELETE of PostgREST filters on a column.
 * pg_graphql's mutations read the rows they change as well. A write that reads a column makes
 * Postgres apply the table's SELECT policies to the rows it changes too (CREATE POLICY, "Policies
 * Applied by Command Type"), so the stranger changes exactly the rows they can read. Measured against
 * a real PostgREST and pg_graphql 1.6.1 on the Supabase image on 24 September 2026
 * (docs/realworld/2026-09-24-write-needs-read.md): with no SELECT policy for them, nothing changes.
 *
 * - `every-row`: a permissive SELECT or ALL policy lets them read with a tautology, and no
 *   RESTRICTIVE one narrows it — or the project switched safeupdate off, and a write without a
 *   filter reads nothing.
 * - `readable-rows`: what they can read is decided by a condition.
 * - `no-row`: no permissive SELECT or ALL policy lets them read at all, or a RESTRICTIVE policy
 *   refuses every row. The write policy is a door that opens the moment someone adds a read policy.
 *
 * A RESTRICTIVE UPDATE or DELETE policy with a condition narrows the write as well; that is not
 * weighed here (only `false`), as before this function existed.
 */
export type WriteReach = "every-row" | "readable-rows" | "no-row";

export interface Reach {
  reach: WriteReach;
  /** For `no-row`: the RESTRICTIVE policy that refuses every row, when that is the reason. */
  refusedBy?: PolicyDetail;
}

/**
 * A predicate that only asks which role is calling: `auth.role() = 'authenticated'`, `auth.uid() is
 * not null`, `(auth.jwt() ->> 'role') = 'service_role'`, as migrations write them and as pg_policies
 * prints them (`(( SELECT auth.role() AS role) = 'authenticated'::text)`). Returns the roles it
 * admits, or null for anything else. The role in a Supabase request is the JWT's: a visitor with the
 * publishable key is anon and has no uid; claiming another role takes a token signed by the project.
 */
export function roleGate(expr: string | null): ReadonlySet<string> | null {
  if (expr === null) return null;
  // String literals are set aside first: a role name is compared as Postgres compares it, case and
  // spaces included (`'Authenticated'` admits nobody).
  const literals: string[] = [];
  let e = expr
    .replace(/'((?:[^']|'')*)'/g, (_, s: string) => `'${literals.push(s.replace(/''/g, "'")) - 1}'`)
    .toLowerCase()
    .replace(/\s+/g, "")
    .replace(/::(text|name|charactervarying)/g, "")
    .replace(/\(selectauth\.(role|uid|jwt)\(\)(as\w+)?\)/g, "auth.$1()");
  for (let prev = ""; prev !== e; ) {
    prev = e;
    e = e.replace(/^\((.*)\)$/, (m, inner: string) => (balanced(inner) ? inner : m));
  }
  if (e === "auth.uid()isnotnull") return new Set(["authenticated"]);
  const who = `(?:auth\\.role\\(\\)|\\(?auth\\.jwt\\(\\)->>'(\\d+)'\\)?)`;
  const m = new RegExp(`^${who}='(\\d+)'$`).exec(e);
  const r = m ?? new RegExp(`^'(\\d+)'=${who}$`).exec(e);
  if (!r) return null;
  // In `auth.jwt() ->> 'role'` the key must be `role`; the other literal is the role name.
  const [key, name] = m ? [m[1], m[2]] : [r[2], r[1]];
  if (key !== undefined && literals[Number(key)] !== "role") return null;
  const role = literals[Number(name)];
  return role !== undefined && /^[a-z_]+$/.test(role) ? new Set([role]) : null;
}

function balanced(s: string): boolean {
  let depth = 0;
  for (const c of s) {
    if (c === "(") depth++;
    else if (c === ")" && --depth < 0) return false;
  }
  return depth === 0;
}

/** Whether a predicate lets a row through for this role: always, never, or it depends on the row. */
function admits(expr: string | null, role: Stranger): "yes" | "no" | "row" {
  if (isTautology(expr)) return "yes";
  if (isContradiction(expr)) return "no";
  const gate = roleGate(expr);
  if (gate) return gate.has(role) ? "yes" : "no";
  return "row";
}

/**
 * Does the policy decide which existing rows are visible? A policy without USING (`for all ... with
 * check (...)` alone) adds nothing to reads, permissive or RESTRICTIVE: Postgres keeps no condition
 * for it (checked on Postgres 17, 24 September 2026).
 */
const reads = (p: PolicyDetail): boolean =>
  (p.command === "select" || p.command === "all") && p.using !== null;

/** Roles every Supabase project has that are neither anon nor authenticated nor a member of them. */
const PLATFORM_ROLES: ReadonlySet<string> = new Set([
  "service_role",
  "postgres",
  "authenticator",
  "supabase_admin",
  "supabase_auth_admin",
  "supabase_storage_admin",
  "supabase_functions_admin",
  "supabase_realtime_admin",
  "supabase_replication_admin",
  "supabase_read_only_user",
  "dashboard_user",
  "pgbouncer",
]);

/**
 * A policy for a role of the project's own (`to site_visitor`): anon or authenticated may be a member
 * of it (`grant site_visitor to anon`), which no scan here reads, so it may let them read.
 */
function viaMembership(p: PolicyDetail): boolean {
  return p.roles.some((r) => {
    const name = r.toLowerCase().replace(/^"|"$/g, "");
    return (
      !["anon", "authenticated", "public"].includes(name) &&
      !PLATFORM_ROLES.has(name) &&
      !/^(?:supabase_|pgsodium_|pg_)/.test(name)
    );
  });
}

export function writeReach(
  t: RlsTable,
  role: Stranger,
  command: "update" | "delete" | "all",
  refusesUnfilteredWrites: boolean,
): Reach {
  const applying = t.policyDetails.filter((p) => appliesTo(p, role));
  const restrictive = applying.filter((p) => !opensAccess(p));
  // A RESTRICTIVE policy that admits no row for this role refuses the write. For a FOR ALL policy
  // only one on every command does: refusing updates alone still leaves reads and deletes. An update
  // also fails when a RESTRICTIVE WITH CHECK refuses every new row.
  const writes = command === "all" ? ["all"] : [command, "all"];
  const refusesWrite = restrictive.find(
    (p) =>
      writes.includes(p.command) &&
      (admits(p.using, role) === "no" || (command === "update" && admits(p.check, role) === "no")),
  );
  if (refusesWrite) return { reach: "no-row", refusedBy: refusesWrite };
  if (!refusesUnfilteredWrites) return { reach: "every-row" };
  const refusesRead = restrictive.find((p) => reads(p) && admits(p.using, role) === "no");
  if (refusesRead) return { reach: "no-row", refusedBy: refusesRead };
  const readers = applying.filter(
    (p) => opensAccess(p) && reads(p) && admits(p.using, role) !== "no",
  );
  const members = t.policyDetails.filter(
    (p) =>
      !appliesTo(p, role) &&
      viaMembership(p) &&
      opensAccess(p) &&
      reads(p) &&
      !isContradiction(p.using),
  );
  if (readers.length === 0 && members.length === 0) return { reach: "no-row" };
  const narrowed = restrictive.some((p) => reads(p) && admits(p.using, role) === "row");
  return {
    reach:
      !narrowed && readers.some((p) => admits(p.using, role) === "yes")
        ? "every-row"
        : "readable-rows",
  };
}

/**
 * The policies that decide what the role can read, so which rows it changes: the permissive ones
 * that let it read (a project role's may, through membership), and the RESTRICTIVE ones whose
 * condition narrows that.
 */
export function readPolicies(t: RlsTable, role: Stranger): PolicyDetail[] {
  return t.policyDetails.filter((p) => {
    if (!reads(p)) return false;
    if (!appliesTo(p, role)) return viaMembership(p) && opensAccess(p) && !isContradiction(p.using);
    return opensAccess(p) ? admits(p.using, role) !== "no" : admits(p.using, role) === "row";
  });
}

/**
 * Functions that may change rows of the table with a stranger's rights, without reading them: in
 * `public` (the schema the Data API exposes), not SECURITY DEFINER (those skip RLS and are another
 * rule's subject), and naming the table after UPDATE, DELETE FROM or MERGE INTO, or running dynamic
 * SQL. A function must be executable by one of the roles, called through `/rest/v1/rpc`; a trigger
 * function need not be, it fires on the stranger's own write to its table. safeupdate does not stop
 * a WHERE that reads no column (`where true`), a BEGIN ATOMIC body (parsed once, at CREATE), or
 * MERGE, and such a write is not limited by any SELECT policy (skeptic review, 24 September 2026).
 * Whether the function reads a column first is not decided here: it is named. What this cannot see
 * (a view over the table, a function in another schema it calls) the finding says in words.
 */
export function changingFunctions(
  fns: readonly SqlFunctionInfo[],
  table: string,
  roles: readonly Stranger[],
): SqlFunctionInfo[] {
  return fns.filter(
    (f) =>
      !f.name.includes(".") &&
      !f.securityDefiner &&
      (f.returns === "trigger" ||
        f.grantedTo.some((g) => (roles as readonly string[]).includes(g))) &&
      (f.changes ?? []).some((c) => c === "*" || c === table),
  );
}

/**
 * Does the role hold one of these privileges on the table, or on a column of it? A PATCH that sets
 * only granted columns goes through without the table privilege (`grant update (v) on t to
 * authenticated`). Column grants are known from a live snapshot only; a migration scan assumes the
 * Supabase default, as `apiReaches` does.
 */
function writeGranted(
  t: RlsTable,
  roles: readonly string[],
  privileges: readonly string[],
): boolean {
  if (apiReaches(t, roles, privileges)) return true;
  const c = t.apiColumnGrants;
  if (!c) return false;
  const everyone = roles.length === 0 || roles.includes("public");
  const held = [
    ...(everyone || roles.includes("anon") ? c.anon : []),
    ...(everyone || roles.includes("authenticated") ? c.authenticated : []),
  ];
  return privileges.some((p) => held.includes(p));
}

const REACH_ORDER: readonly WriteReach[] = ["every-row", "readable-rows", "no-row"];

/**
 * The reach of each stranger a write policy applies to and holds the write privilege, and the widest
 * of them, anon first on a tie: a policy with no TO clause applies to signed-in users too, and they
 * may read what anon cannot.
 */
export function widestReach(
  t: RlsTable,
  p: PolicyDetail,
  command: "update" | "delete" | "all",
  refusesUnfilteredWrites: boolean,
): Reach & { stranger: Stranger; byRole: Partial<Record<Stranger, Reach>> } {
  const byRole: Partial<Record<Stranger, Reach>> = {};
  let best: (Reach & { stranger: Stranger }) | null = null;
  for (const s of ["anon", "authenticated"] as const) {
    if (!appliesTo(p, s) || !writeGranted(t, [s], writePrivileges(p.command))) continue;
    const r = writeReach(t, s, command, refusesUnfilteredWrites);
    byRole[s] = r;
    if (best === null || REACH_ORDER.indexOf(r.reach) < REACH_ORDER.indexOf(best.reach))
      best = { ...r, stranger: s };
  }
  return { ...(best ?? { reach: "no-row", stranger: "anon" }), byRole };
}

/**
 * A FOR ALL policy whose WITH CHECK (or, without one, its USING) is a tautology also lets strangers
 * add rows, whatever they can read: an insert reads no existing row. The first stranger that holds
 * the privilege and whom no RESTRICTIVE insert or all policy refuses, or null.
 */
function insertOpen(t: RlsTable, p: PolicyDetail, strangers: readonly Stranger[]): Stranger | null {
  if (p.command !== "all" || !isTautology(p.check ?? p.using)) return null;
  for (const s of strangers) {
    if (!writeGranted(t, [s], ["insert"])) continue;
    const refused = t.policyDetails.some(
      (q) =>
        !opensAccess(q) &&
        appliesTo(q, s) &&
        (q.command === "insert" || q.command === "all") &&
        admits(q.check ?? q.using, s) === "no",
    );
    if (!refused) return s;
  }
  return null;
}

/**
 * A write policy open to anon (or to PUBLIC) whose predicate is a tautology: anyone holding the
 * public key writes the table through PostgREST, no application code required. An INSERT-only policy
 * is the shape deliberate public forms use, so it is reported one severity lower; update, delete and
 * `for all` can change or destroy rows that belong to someone else — the rows the stranger can read
 * (`writeReach`). Where a live database shows they can read none, the finding is a lead: nothing
 * changes today through the table and GraphQL endpoints, and one added read policy opens it. A
 * migration scan cannot show that a policy is absent (the dashboard, functions, SQL it does not
 * evaluate), so there such a finding keeps its claim; where the migrations hold policy statements the
 * parser does not evaluate (`policiesUnread`), even the narrower wordings fall back to it.
 */
export const anonWritePolicy: Rule = {
  id: "supabase.anon-write-policy",
  title: "Write policy open to anon or every role",
  description:
    "An insert, update or delete policy targets anon (or omits the TO clause, which means PUBLIC) and decides with `true`. Anyone holding the public anon key writes the table directly through PostgREST, including rows that belong to signed-in users, whether or not the application has a form for it.",
  severity: "high",
  confidence: 0.85,
  cwe: ["CWE-284", "CWE-862"],
  evaluate(ctx) {
    const out: Finding[] = [];
    // Unknown (every migration scan, and snapshots taken before the query read it) is the Supabase
    // default: the API role refuses an update or delete without a filter.
    const refuses = ctx.model.dataApiRefusesUnfilteredWrites !== false;
    for (const t of publicTables(ctx)) {
      // A table without RLS is already the subject of policies-without-rls-enabled or
      // table-without-rls; one root cause, one finding.
      if (!t.rlsEnabled) continue;
      for (const p of t.policyDetails) {
        if (!WRITE_COMMANDS.has(p.command) || !reachableByAnon(p) || !opensAccess(p)) continue;
        if (!writeGranted(t, p.roles, writePrivileges(p.command))) continue;
        const decides: Array<[string, string | null]> =
          p.command === "insert"
            ? [["WITH CHECK", p.check]]
            : p.command === "all"
              ? [
                  ["USING", p.using],
                  ["WITH CHECK", p.check],
                ]
              : [["USING", p.using]];
        const open = decides.filter(([, expr]) => isTautology(expr));
        if (open.length === 0) continue;
        const clause = open.map(([kind, expr]) => `${kind} ${quote(expr)}`).join(" / ");
        const strangers = (["anon", "authenticated"] as const).filter((r) => appliesTo(p, r));
        const facts = describe(ctx, t, p, strangers, refuses);
        const evidence: Evidence[] = [
          {
            kind: "rule",
            summary: `Policy "${p.name}" on public.${t.table} is ${commandLabel(p)} to ${roleLabel(p)} and decides with a tautology: ${clause}. ${facts.consequence}`,
            locations: locations(p.location, t.location),
            data: {
              deterministic: true,
              ruleId: this.id,
              table: t.table,
              policy: p.name,
              command: p.command,
              roles: p.roles,
              ...facts.data,
            },
          },
          {
            kind: "trace",
            summary: [
              facts.data.stranger === "authenticated"
                ? "Anyone who signs up"
                : "Anyone with the public anon key",
              "PostgREST",
              `policy "${p.name}" (${commandLabel(p)}, to ${roleLabel(p)}, ${clause})`,
              `public.${t.table}`,
            ].join(" -> "),
          },
        ];
        const f = finding(
          ctx,
          this,
          {
            title: facts.title,
            entrypoints: [DATA_API],
            sources: ["anon-key"],
            sinks: [`supabase.${p.command === "all" ? "insert" : p.command}:public.${t.table}`],
            path: [
              "Anyone with the public anon key",
              "PostgREST",
              `policy "${p.name}" (${commandLabel(p)}, to ${roleLabel(p)})`,
              `public.${t.table}`,
            ],
            evidence,
          },
          facts.severity,
        );
        // Nothing changes today, so the product may not claim a hole: a lead (tiers.ts keeps it one).
        out.push(facts.lead ? { ...f, tier: "lead" } : f);
      }
    }
    return out;
  },
};

const HOW_API_WRITES =
  "Through the Data API a change reads the rows it changes: every PostgREST PATCH and DELETE filters on a column (Supabase refuses one without a filter for the API role: safeupdate), and a pg_graphql mutation returns the rows it changed. A change that reads the table makes Postgres apply its SELECT policies to those rows too";

/** What the finding says about one open write policy: title, the consequence, the data, the tier. */
function describe(
  ctx: RuleContext,
  t: RlsTable,
  p: PolicyDetail,
  strangers: readonly Stranger[],
  refuses: boolean,
): {
  title: string;
  consequence: string;
  severity: Severity;
  lead: boolean;
  data: Record<string, unknown>;
} {
  const table = `public.${t.table}`;
  const live = ctx.model.fromLiveDatabase === true;
  if (p.command === "insert")
    return {
      title: `Policy "${p.name}" lets anyone insert "${t.table}"`,
      consequence: `Anyone holding the public anon key can insert rows in ${table} straight through PostgREST, without going through this application. An insert-only policy is how deliberate public forms are written, so this is reported as medium: check that the table is meant to accept rows from strangers and that a rate limit and a validation trigger exist.`,
      severity: "medium",
      lead: false,
      data: {},
    };
  const action = p.command === "all" ? "write" : p.command;
  const verbs = p.command === "all" ? "insert, update and delete" : `${p.command} rows in`;
  const everyRow = (stranger: Stranger, extra: string): ReturnType<typeof describe> => ({
    title: `Policy "${p.name}" lets anyone${stranger === "authenticated" ? " who signs up" : ""} ${action} "${t.table}"`,
    consequence: `${stranger === "authenticated" ? "Anyone who signs up" : "Anyone holding the public anon key"} can ${verbs} ${table} straight through PostgREST, without going through this application. Rows that belong to signed-in users can be changed or deleted by a stranger.${extra}`,
    severity: "high",
    lead: false,
    data: {},
  });
  // Which rows change is decided by USING; a FOR ALL policy open only by its WITH CHECK is weighed
  // as before this distinction existed.
  if (p.command === "select" || !isTautology(p.using)) return everyRow("anon", "");
  const r = widestReach(t, p, p.command, refuses);
  const unread = t.policiesUnread === true || ctx.model.policiesUnread === true;
  // Anything short of "anon changes every row" rests on a policy being absent, or on one the parser
  // may have kept after the database dropped it.
  if (unread && (r.reach !== "every-row" || r.stranger !== "anon"))
    return {
      ...everyRow(
        "anon",
        " A policy statement this scan does not evaluate (inside a DO block, an ALTER POLICY, or dynamic SQL) names this table, so what strangers can read, and so which rows a change through the Data API reaches, is not known from the migrations; this states the widest case. A snapshot of the live database settles it.",
      ),
      data: { reach: "every-row", stranger: "anon", policiesUnread: true },
    };
  const readersOf = (s: Stranger) => readPolicies(t, s);
  const list = (ps: readonly PolicyDetail[]) =>
    ps
      .map((q) => `"${q.name}"${opensAccess(q) ? "" : " (RESTRICTIVE)"} USING ${quote(q.using)}`)
      .join(", ");
  const reachers = (Object.keys(r.byRole) as Stranger[]).filter(
    (s) => r.byRole[s]?.reach !== "no-row",
  );
  const readers = [...new Set(reachers.flatMap(readersOf))];
  const base = {
    reach: r.reach,
    stranger: r.stranger,
    readPolicies: readers.map((q) => q.name),
  };
  if (r.reach === "every-row") {
    let extra = "";
    if (!refuses)
      extra = ` This project's Data API accepts an update or delete without a filter (safeupdate is not in force for authenticator), so the table's SELECT policies do not limit it.`;
    else if (r.stranger === "authenticated") {
      const anon = r.byRole.anon?.reach;
      extra = ` Signed-in users may read every row (${list(readersOf("authenticated"))}). ${
        anon === "readable-rows"
          ? `A visitor without an account changes the rows they can read (${list(readersOf("anon"))}).`
          : live
            ? "A visitor without an account changes none: through the Data API a change reads the rows it changes, and no policy lets anon read them."
            : "The migrations show no policy that lets a visitor without an account read them; a snapshot of the live database settles whether the database has one."
      }`;
    } else if (p.command !== "all")
      extra = ` They can read every row too (${list(readersOf("anon"))}), and a change through the Data API reaches every row they can read.`;
    return { ...everyRow(r.stranger, extra), data: base };
  }
  const writers =
    !r.refusedBy || r.refusedBy.command === "select"
      ? changingFunctions(ctx.model.sqlFunctions ?? [], t.table, strangers)
      : [];
  const names = writers.map((w) => `${w.name}()`).join(", ");
  const writerNoun = writers.length === 1 ? `function ${names}` : `functions ${names}`;
  const writerVerb = "can change";
  const BLIND =
    "a write that reads no column (WHERE true, a BEGIN ATOMIC body, MERGE, dynamic SQL) is limited by neither safeupdate nor the read policies, and then reaches every row this policy allows";
  const functionsNote =
    writers.length > 0
      ? ` But ${writerNoun}, which run${writers.length === 1 ? "s" : ""} with the stranger's rights (called through /rest/v1/rpc, or as a trigger on their own write), ${writerVerb} ${table}: ${BLIND}. Check ${writers.length === 1 ? "it" : "them"} first.`
      : ` No function in the schema is seen changing it; one that does, with the caller's rights (directly, as a trigger, through a view or a function in another schema), would matter: ${BLIND}.`;
  const data = {
    ...base,
    ...(r.refusedBy ? { refusedBy: r.refusedBy.name } : {}),
    ...(writers.length > 0 ? { writers: writers.map((w) => w.name) } : {}),
  };
  if (r.reach === "readable-rows") {
    const whose = reachers
      .map(
        (s) =>
          `what ${s === "anon" ? "a visitor without an account" : "a signed-in user"} can read is decided by ${list(readersOf(s))}`,
      )
      .join("; ");
    return {
      title: `Policy "${p.name}" lets anyone ${action} the rows of "${t.table}" they can read`,
      consequence: `${r.stranger === "authenticated" ? "Anyone who signs up" : "Anyone holding the public anon key"} can ${p.command === "all" ? "update and delete" : p.command} the rows of ${table} they can read, straight through PostgREST. ${HOW_API_WRITES}. ${whose.charAt(0).toUpperCase()}${whose.slice(1)}.${writers.length > 0 ? functionsNote : ""}`,
      severity: "high",
      lead: false,
      data,
    };
  }
  // No row through the table endpoints, as far as the policies show. Only a live database shows
  // every policy: a migration scan misses the ones made in the dashboard, by a function a later
  // statement calls, or in SQL it does not evaluate (skeptic review, 24 September 2026), so there the
  // finding keeps its claim and says what would settle it.
  if (!live)
    return {
      ...everyRow(
        "anon",
        ` Through the Data API a change reaches only the rows the stranger can read, and the migrations show no policy that lets them read ${table}: if the live database has none either, this changes no row through the table and GraphQL endpoints today. Policies made in the dashboard or by SQL this scan does not evaluate count as well, so the finding stands until a snapshot of the live database says otherwise.`,
      ),
      data: { ...data, readPolicies: [], migrationsOnly: true },
    };
  // A FOR ALL policy still lets them add rows.
  const adder = insertOpen(t, p, strangers);
  if (adder)
    return {
      title: `Policy "${p.name}" lets anyone${adder === "authenticated" ? " who signs up" : ""} add rows to "${t.table}"`,
      consequence: `${adder === "authenticated" ? "Anyone who signs up" : "Anyone holding the public anon key"} can add rows to ${table} straight through PostgREST: an insert reads no existing row. Changing or deleting rows reaches none today (${
        r.refusedBy
          ? `RESTRICTIVE policy "${r.refusedBy.name}" refuses every row`
          : "no policy lets them read the table"
      }), so this is reported like an open insert policy, as medium.${writers.length > 0 ? functionsNote : ""}`,
      severity: "medium",
      lead: false,
      data: { ...data, reach: "add-rows", stranger: adder },
    };
  const why = r.refusedBy
    ? `RESTRICTIVE policy "${r.refusedBy.name}" (${commandLabel(r.refusedBy)}) refuses every row`
    : `no policy lets anon${strangers.includes("authenticated") ? " or signed-in users" : ""} read ${table}`;
  return {
    title:
      writers.length > 0
        ? `Policy "${p.name}" would let anyone ${action} "${t.table}"; no policy lets them read it, but ${writerNoun} ${writerVerb} it`
        : r.refusedBy
          ? `Policy "${p.name}" would let anyone ${action} "${t.table}", but RESTRICTIVE policy "${r.refusedBy.name}" refuses every row`
          : `Policy "${p.name}" would let anyone ${action} "${t.table}", but no policy lets them read it`,
    consequence: `${HOW_API_WRITES}, so through the table and GraphQL endpoints a stranger changes only rows they can read, and today they can read none: ${why}. ${r.refusedBy ? "It opens if that policy is dropped" : "It opens the moment a SELECT policy for these roles is added"}, or if safeupdate is switched off for authenticator (alter role authenticator set safeupdate.enabled = off, or a PostgREST pre-request function that does it).${functionsNote} A place to look, not a hole found.`,
    severity: "high",
    lead: true,
    data: { ...data, readPolicies: [] },
  };
}

/** A permissive select (or `for all`) policy for anon that lets every row through: the table is public already. */
function selectOpenToAnon(t: RlsTable): boolean {
  return t.policyDetails.some(
    (p) =>
      (p.command === "select" || p.command === "all") &&
      opensAccess(p) &&
      reachableByAnon(p) &&
      isTautology(p.using),
  );
}

/**
 * A view runs with its owner's rights unless it says `security_invoker`, and on Supabase the owner
 * is postgres, whom row level security does not bind. So a view over a protected table shows every
 * row of it to whoever may select the view, and the default grants let both API roles select it.
 * Supabase's own lint reports the shape as 0010. A view is often meant to publish a subset, which
 * is why this is a lead: the fact is read from the database, the intent is the owner's to state.
 */
export const viewRunsWithOwnerRights: Rule = {
  id: "supabase.view-runs-with-owner-rights",
  title: "View runs with its owner's rights over a protected table",
  description:
    "A view in the public schema was created without `security_invoker`, so it runs as its owner, postgres, and the row level security of the tables it selects from does not apply inside it. Anyone the grants let select the view reads every row of those tables through PostgREST, policies or not. Supabase's own lint reports the same shape as 0010.",
  severity: "high",
  confidence: 0.8,
  cwe: ["CWE-284", "CWE-862"],
  evaluate(ctx) {
    const out: Finding[] = [];
    const byKey = new Map(ctx.model.tables.map((t) => [t.table, t]));
    for (const v of publicTables(ctx)) {
      if (!isView(v) || v.viewSecurityInvoker !== false || !v.viewSources) continue;
      // The Data API refuses before the view runs unless an API role may select it.
      if (!apiReaches(v, [], ["select"])) continue;
      // Tables whose rows the view hands out: protected by RLS, not public already, not views.
      const shown = v.viewSources
        .map((k) => byKey.get(k))
        .filter((t): t is RlsTable => t !== undefined && !isView(t) && t.rlsEnabled)
        .filter((t) => !selectOpenToAnon(t));
      if (shown.length === 0) continue;
      const anon = apiReaches(v, ["anon"], ["select"]);
      const who = anon ? "anyone holding the public anon key" : "any signed-in user";
      const what = v.kind === "matview" ? "materialized view" : "view";
      const names = shown.map((t) => `public.${t.table}`).join(", ");
      const exact = v.sqlName ?? v.table;
      const fix =
        v.kind === "matview"
          ? `revoke select on public.${exact} from anon, authenticated; -- or refresh it from a query that keeps only what everyone may see`
          : `alter view public.${exact} set (security_invoker = on); -- the caller's policies then apply inside the view`;
      const evidence: Evidence[] = [
        {
          kind: "rule",
          summary: `public.${v.table} is a ${what} over ${names}, created without security_invoker, so it runs with its owner's rights and the row level security of ${shown.length === 1 ? "that table" : "those tables"} does not apply inside it. ${who[0]?.toUpperCase()}${who.slice(1)} may select the ${what}, so they read every row it selects through PostgREST, whatever the policies on ${names} say. If the ${what} is meant to publish exactly this, say so with audit.config.json publicTables; otherwise: ${fix}`,
          locations: locations(v.location, shown[0]?.location),
          data: {
            deterministic: true,
            ruleId: this.id,
            table: v.table,
            materialized: v.kind === "matview",
            sources: shown.map((t) => t.table),
            anon,
          },
        },
        {
          kind: "trace",
          summary: [
            anon ? "Anyone with the public anon key" : "Any signed-in user",
            "PostgREST",
            `public.${v.table} (${what}, owner's rights, no security_invoker)`,
            `${names} (RLS on, not applied inside the ${what})`,
          ].join(" -> "),
        },
      ];
      out.push(
        finding(
          ctx,
          this,
          {
            title: `View "${v.table}" shows ${shown.map((t) => `"${t.table}"`).join(", ")} with its owner's rights`,
            entrypoints: [DATA_API],
            sources: ["anon-key"],
            sinks: shown.map((t) => `supabase.select:public.${t.table}`),
            path: [
              anon ? "Anyone with the public anon key" : "Any signed-in user",
              "PostgREST",
              `public.${v.table} (${what} without security_invoker)`,
              names,
            ],
            evidence,
          },
          anon ? "high" : "medium",
        ),
      );
    }
    return out;
  },
};

/** Rules that read the migrations only; no query from the application is required. */
export const supabaseSqlPoliciesPack: readonly Rule[] = [
  rlsPolicyTrustsUserMetadata,
  policiesWithoutRlsEnabled,
  anonWritePolicy,
  viewRunsWithOwnerRights,
];
