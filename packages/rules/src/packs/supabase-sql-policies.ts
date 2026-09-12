import type { Evidence, Finding, Severity } from "@auditai/core";
import type { FileRef, PolicyDetail, RlsTable } from "@auditai/parser";
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
      if (t.rlsEnabled || t.policyDetails.length === 0) continue;
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
function isTautology(expr: string | null): boolean {
  if (expr === null) return false;
  return /^\(*\s*true\s*\)*$/i.test(expr.trim());
}

const ANON_ROLES = new Set(["anon", "public"]);

/** Does the policy apply to the anonymous role? No TO clause means PUBLIC, which includes anon. */
function reachableByAnon(p: PolicyDetail): boolean {
  if (p.roles.length === 0) return true;
  return p.roles.some((r) => ANON_ROLES.has(r.toLowerCase().replace(/^"|"$/g, "")));
}

const WRITE_COMMANDS = new Set(["insert", "update", "delete", "all"]);

/**
 * A write policy open to anon (or to PUBLIC) whose predicate is a tautology: anyone holding the
 * public key writes the table through PostgREST, no application code required. An INSERT-only policy
 * is the shape deliberate public forms use, so it is reported one severity lower; update, delete and
 * `for all` can change or destroy rows that belong to someone else.
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
    for (const t of publicTables(ctx)) {
      // A table without RLS is already the subject of policies-without-rls-enabled or
      // table-without-rls; one root cause, one finding.
      if (!t.rlsEnabled) continue;
      for (const p of t.policyDetails) {
        if (!WRITE_COMMANDS.has(p.command) || !reachableByAnon(p)) continue;
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
        const insertOnly = p.command === "insert";
        const severity: Severity = insertOnly ? "medium" : "high";
        const clause = open.map(([kind, expr]) => `${kind} ${quote(expr)}`).join(" / ");
        const verbs = p.command === "all" ? "insert, update and delete" : `${p.command} rows in`;
        const evidence: Evidence[] = [
          {
            kind: "rule",
            summary: `Policy "${p.name}" on public.${t.table} is ${commandLabel(p)} to ${roleLabel(p)} and decides with a tautology: ${clause}. Anyone holding the public anon key can ${verbs} public.${t.table} straight through PostgREST, without going through this application.${insertOnly ? " An insert-only policy is how deliberate public forms are written, so this is reported as medium: check that the table is meant to accept rows from strangers and that a rate limit and a validation trigger exist." : " Rows that belong to signed-in users can be changed or deleted by a stranger."}`,
            locations: locations(p.location, t.location),
            data: {
              deterministic: true,
              ruleId: this.id,
              table: t.table,
              policy: p.name,
              command: p.command,
              roles: p.roles,
            },
          },
          {
            kind: "trace",
            summary: [
              "Anyone with the public anon key",
              "PostgREST",
              `policy "${p.name}" (${commandLabel(p)}, to ${roleLabel(p)}, ${clause})`,
              `public.${t.table}`,
            ].join(" -> "),
          },
        ];
        out.push(
          finding(
            ctx,
            this,
            {
              title: `Policy "${p.name}" lets anyone ${p.command === "all" ? "write" : p.command} "${t.table}"`,
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
            severity,
          ),
        );
      }
    }
    return out;
  },
};

/** Rules that read the migrations only; no query from the application is required. */
export const supabaseSqlPoliciesPack: readonly Rule[] = [
  rlsPolicyTrustsUserMetadata,
  policiesWithoutRlsEnabled,
  anonWritePolicy,
];
