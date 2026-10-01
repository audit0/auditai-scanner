import type { Finding } from "@auditai/core";
import {
  type FileRef,
  isRoleValue,
  type RlsTable,
  recursivePolicies,
  SNAPSHOT_REF,
  scopeColumnsIn,
} from "@auditai/parser";
import type { Rule, RuleContext } from "../rule.js";
import { privilegeSources } from "./self-assignable-role.js";
import { sqlFunctionsOf } from "./sql-functions.js";

/**
 * S7. A function fired on INSERT into auth.users (the usual `handle_new_user`) fills a column of the
 * new user's row unchanged from `new.raw_user_meta_data`, and that column decides a privilege (a
 * route's role check, an `is_admin()`-style helper or a policy; the same sources as S6). The client
 * writes that metadata in `supabase.auth.signUp({ options: { data } })`, so anyone signs up as admin.
 *
 * The same copy into the column that says which tenant the user belongs to (an `organisation_id` the
 * policies scope by, directly or through a `get_my_org_id()`-style helper) lets anyone who learns a
 * tenant's id sign up inside it.
 *
 * Silent when the value is chosen among literals (CASE, IN), when a BEFORE INSERT trigger on the
 * target table holds the column back, when the column is an enum with no admin-like label, and on a
 * live snapshot, which carries no triggers.
 */
/** Enum labels that can carry a privilege (`tenant_admin`, `store_manager`, `platform_owner`). */
const PRIVILEGED_LABEL = /admin|owner|super|manager|staff|moderator|operator|root/i;

export const roleFromSignupMetadata: Rule = {
  id: "supabase.role-from-signup-metadata",
  title: "Sign-up trigger copies a role from user metadata into the profile",
  description:
    "A trigger on auth.users copies a value from raw_user_meta_data, which the client sets in supabase.auth.signUp({ options: { data } }), into a column that decides admin access or the tenant the user belongs to. Anyone who can create an account signs up as admin, or inside any tenant whose id they know.",
  severity: "critical",
  confidence: 0.85,
  cwe: ["CWE-269", "CWE-915"],
  evaluate(ctx) {
    const triggers = ctx.model.sqlTriggers ?? [];
    const signup = new Map(
      triggers
        .filter((t) => t.table === "auth.users" && t.events.includes("insert"))
        .map((t) => [t.function, t]),
    );
    if (signup.size === 0) return [];
    const sources = privilegeSources(ctx);
    const tenants = tenantSources(ctx);
    const enums = ctx.model.enums ?? {};
    const out: Finding[] = [];
    for (const fn of sqlFunctionsOf(ctx.model)) {
      const trigger = signup.get(fn.name);
      if (!trigger || fn.location.file === SNAPSHOT_REF.file) continue;
      for (const copy of fn.metadataCopies ?? []) {
        const src = sources.get(`${copy.table}.${copy.column}`);
        if (!src) {
          const scope = tenants.get(`${copy.table}.${copy.column}`);
          if (scope) out.push(...tenantFinding(ctx, this, fn, trigger, copy, scope, triggers));
          continue;
        }
        const t = ctx.model.tables.find((x) => x.table === copy.table);
        if (!t || !t.columns.includes(copy.column)) continue;
        // An enum that cannot hold an admin-like value makes the copy a persona, not a privilege.
        const type = t.columnInfo?.[t.columns.indexOf(copy.column)]?.type.replace(/\[\]$/, "");
        const labels = type === undefined ? undefined : enums[type];
        if (labels && !labels.some((l) => isRoleValue(l) || PRIVILEGED_LABEL.test(l))) continue;
        const held = triggers.some(
          (tr) =>
            tr.table === t.table &&
            tr.timing === "before" &&
            tr.events.includes("insert") &&
            (tr.forcedColumns ?? []).includes(copy.column),
        );
        if (held) continue;
        const col = `${t.table}.${copy.column}`;
        const path = [
          "POST /auth/v1/signup",
          `supabase.auth.signUp({ options: { data: { ${copy.key}: 'admin' } } })`,
          `trigger ${trigger.name} on auth.users -> ${fn.name}() writes ${col} = raw_user_meta_data ->> '${copy.key}'`,
          ...src.via.slice(0, 3).map((v) => `read as a privilege by ${v}`),
        ];
        const doubt = recursionDoubt(
          ctx,
          t,
          src.via.flatMap((v) =>
            [...v.matchAll(/SQL function ([\w.]+)\(\)/g)].map((m) => m[1] ?? ""),
          ),
        );
        out.push({
          id: ctx.nextId(),
          ruleId: this.id,
          status: doubt ? "candidate" : "likely",
          severity: this.severity,
          confidence: doubt ? 0.5 : this.confidence,
          cwe: this.cwe,
          createdAt: ctx.now,
          updatedAt: ctx.now,
          title: `Sign-up metadata "${copy.key}" becomes "${col}", which grants privileges`,
          entrypoints: ["POST /auth/v1/signup", ...src.entries],
          sources: [`signup metadata:${copy.key}`],
          sinks: [`supabase.insert:public.${t.table}`],
          path,
          evidence: [
            {
              kind: "rule",
              summary: `${fn.name}() runs on every new row of auth.users (trigger ${trigger.name}, ${trigger.location.file}:${trigger.location.line}) and fills public.${col} unchanged from raw_user_meta_data ->> '${copy.key}'. The client writes that metadata itself in supabase.auth.signUp({ options: { data } }), and public.${col} decides a privilege: it is read by ${src.via.join("; ")}. Anyone who can create an account signs up with ${copy.key} set to an admin value. Allow-list the non-privileged values with a safe default (case when ... in (...) then ... else '<default>' end), or leave the column at its default and let the server promote admins with the service role.${doubt ?? ""}`,
              locations: locations(fn.location, trigger.location, ...src.refs),
              data: {
                deterministic: false,
                ruleId: this.id,
                function: fn.name,
                trigger: trigger.name,
                table: t.table,
                column: copy.column,
                metadataKey: copy.key,
                ...(doubt ? { recursivePolicies: recursivePolicies(t) } : {}),
              },
            },
            { kind: "trace", summary: path.join(" -> ") },
          ],
        });
      }
    }
    return out;
  },
};

interface TenantSource {
  via: string[];
  refs: FileRef[];
  policies: number;
  /** Helper functions policies call to read the column. */
  helpers: string[];
}

/** Tenant columns of the caller's own row that policies scope by, keyed `table.column`, with where. */
export function tenantSources(ctx: RuleContext): Map<string, TenantSource> {
  const out = new Map<string, TenantSource>();
  const add = (table: string, column: string, via: string, ref: FileRef, helper?: string): void => {
    const key = `${table}.${column}`;
    const s = out.get(key) ?? { via: [], refs: [], policies: 0, helpers: [] };
    s.policies += 1;
    if (helper !== undefined && !s.helpers.includes(helper)) s.helpers.push(helper);
    if (s.via.length < 3 && !s.via.includes(via)) s.via.push(via);
    if (s.refs.length < 3 && !s.refs.some((r) => r.file === ref.file && r.line === ref.line))
      s.refs.push(ref);
    out.set(key, s);
  };
  const fns = sqlFunctionsOf(ctx.model);
  const byBare = new Map(fns.map((f) => [f.name.split(".").pop() ?? f.name, f]));
  // A helper a policy calls, or one it calls in turn (`get_org_id()` -> `get_org_id_safe()`).
  const readers = (name: string): SqlFn[] => {
    const f = byBare.get(name);
    if (!f) return [];
    const inner = (f.calls ?? [])
      .map((c) => byBare.get(c.split(".").pop() ?? c))
      .filter((g): g is SqlFn => g !== undefined);
    return [f, ...inner].filter((g) => (g.scopeColumns ?? []).length > 0);
  };
  const called = [...byBare.keys()];
  for (const t of ctx.model.tables) {
    for (const p of t.policyDetails) {
      const expr = [p.using, p.check].filter((e): e is string => !!e).join(" and ");
      if (expr === "") continue;
      const where = `policy "${p.name}" on ${t.table} (${p.location.file}:${p.location.line})`;
      for (const sc of scopeColumnsIn(`select ${expr}`))
        add(sc.table, sc.column, where, p.location);
      for (const bare of called) {
        if (!new RegExp(`(?<![A-Za-z0-9_$])${bare}\\s*\\(`, "i").test(expr)) continue;
        for (const f of readers(bare))
          for (const sc of f.scopeColumns ?? [])
            add(sc.table, sc.column, `${where} through ${f.name}()`, p.location, f.name);
      }
    }
  }
  return out;
}

type SqlFn = ReturnType<typeof sqlFunctionsOf>[number];
type Copy = NonNullable<SqlFn["metadataCopies"]>[number];
type Trigger = NonNullable<RuleContext["model"]["sqlTriggers"]>[number];

function tenantFinding(
  ctx: RuleContext,
  rule: Rule,
  fn: SqlFn,
  trigger: Trigger,
  copy: Copy,
  scope: TenantSource,
  triggers: readonly Trigger[],
): Finding[] {
  const t = ctx.model.tables.find((x) => x.table === copy.table);
  if (!t || !t.columns.includes(copy.column)) return [];
  // A BEFORE INSERT trigger that overrides or checks the column (an invitation lookup that raises).
  const held = triggers.some(
    (tr) =>
      tr.table === t.table &&
      tr.timing === "before" &&
      tr.events.includes("insert") &&
      ((tr.forcedColumns ?? []).includes(copy.column) || tr.checkedColumns.includes(copy.column)),
  );
  if (held) return [];
  const col = `${t.table}.${copy.column}`;
  const count = `${scope.policies} ${scope.policies === 1 ? "policy scopes" : "policies scope"}`;
  const path = [
    "POST /auth/v1/signup",
    `supabase.auth.signUp({ options: { data: { ${copy.key}: '<another tenant id>' } } })`,
    `trigger ${trigger.name} on auth.users -> ${fn.name}() writes ${col} = raw_user_meta_data ->> '${copy.key}'`,
    `${count} rows by ${col}`,
  ];
  const doubt = recursionDoubt(ctx, t, scope.helpers);
  return [
    {
      id: ctx.nextId(),
      ruleId: rule.id,
      status: doubt ? "candidate" : "likely",
      severity: "high",
      confidence: doubt ? 0.5 : 0.75,
      cwe: rule.cwe,
      createdAt: ctx.now,
      updatedAt: ctx.now,
      title: `Sign-up metadata "${copy.key}" becomes "${col}", the tenant the policies scope by`,
      entrypoints: ["POST /auth/v1/signup"],
      sources: [`signup metadata:${copy.key}`],
      sinks: [`supabase.insert:public.${t.table}`],
      path,
      evidence: [
        {
          kind: "rule",
          summary: `${fn.name}() runs on every new row of auth.users (trigger ${trigger.name}, ${trigger.location.file}:${trigger.location.line}) and fills public.${col} unchanged from raw_user_meta_data ->> '${copy.key}'. The client writes that metadata itself in supabase.auth.signUp({ options: { data } }), and ${count} other rows by the caller's ${copy.column}, for example ${scope.via.join("; ")}. Anyone who learns a tenant's id (from a URL, an invitation link or a public page) signs up with it and reads that tenant's data as a member. Leave the column empty at sign-up and attach users to a tenant only from the server, after checking an invitation; if accounts are only created by admins, also turn off public sign-ups in Supabase Auth.${doubt ?? ""}`,
          locations: locations(fn.location, trigger.location, ...scope.refs),
          data: {
            deterministic: false,
            ruleId: rule.id,
            kind: "tenant",
            function: fn.name,
            trigger: trigger.name,
            table: t.table,
            column: copy.column,
            metadataKey: copy.key,
            policies: scope.policies,
            ...(doubt ? { recursivePolicies: recursivePolicies(t) } : {}),
          },
        },
        { kind: "trace", summary: path.join(" -> ") },
      ],
    },
  ];
}

/**
 * The sign-up copy itself runs in a SECURITY DEFINER trigger, but the column only matters where it is
 * read. When a SELECT policy of the table reads the table itself (42P17 as the migrations stand) and
 * no reader goes around RLS through a SECURITY DEFINER function, no check works as written, so the
 * live policies must differ: a caveat to append, or null when the finding stands as it is.
 */
function recursionDoubt(ctx: RuleContext, t: RlsTable, readers: readonly string[]): string | null {
  const recursive = recursivePolicies(t);
  if (recursive.length === 0) return null;
  const fns = sqlFunctionsOf(ctx.model);
  // A SECURITY DEFINER reader counts only when something calls it: a policy, another function or an rpc.
  const policyText = ctx.model.tables
    .flatMap((x) => x.policyDetails.flatMap((p) => [p.using ?? "", p.check ?? ""]))
    .join("\n");
  const called = (name: string): boolean => {
    const bare = name.split(".").pop() ?? name;
    return (
      new RegExp(`(?<![A-Za-z0-9_$])${bare}\\s*\\(`, "i").test(policyText) ||
      fns.some((f) => (f.calls ?? []).some((c) => (c.split(".").pop() ?? c) === bare)) ||
      ctx.model.routes.some((r) =>
        r.queries.some((q) => q.operation === "rpc" && (q.table.split(".").pop() ?? "") === bare),
      )
    );
  };
  const bypass = readers.some((name) =>
    fns.some((f) => f.name === name && f.securityDefiner && called(name)),
  );
  if (bypass) return null;
  return ` Caveat: policy ${recursive.map((n) => `"${n}"`).join(" and ")} on public.${t.table} reads public.${t.table} itself, so as the migrations stand Postgres answers every check that reads the column under RLS with "infinite recursion detected in policy" (42P17). A working application means the live policies differ: read them (select * from pg_policies where tablename = '${t.table}') before trusting or dismissing this finding.`;
}

function locations(...refs: FileRef[]): FileRef[] {
  const out: FileRef[] = [];
  for (const r of refs) if (!out.some((o) => o.file === r.file && o.line === r.line)) out.push(r);
  return out;
}
