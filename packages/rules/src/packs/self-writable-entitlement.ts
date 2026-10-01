import type { Finding } from "@auditai/core";
import {
  entitlementColumnsIn,
  type FileRef,
  type RlsTable,
  recursivePolicies,
  SNAPSHOT_REF,
} from "@auditai/parser";
import type { Rule, RuleContext } from "../rule.js";
import { type OpenPath, rowsGetCreated, selfWritePath } from "./self-assignable-role.js";
import { sqlFunctionsOf } from "./sql-functions.js";

/**
 * S8. A column of the caller's own row holds what they paid for or may spend (credits, a balance,
 * points, a plan or tier, a KYC status), something on the server decides on it (a route that exits
 * when `profile.credits <= 0`, a SQL function or policy that compares it), and the same user may
 * rewrite it through the Data API by S6's write path: a permissive own-row UPDATE (or ALL) policy
 * whose WITH CHECK leaves the column free, no column privilege and no BEFORE trigger naming it, or
 * delete and re-insert. The billing twin of S6 (hatex-terminal, docs/realworld/2026-09-26-candidate-hunt.md).
 *
 * A column name alone is not enough (a corpus scan found 206 self-writable columns with such names,
 * mostly meal plans and game points): without a decision on it the rule stays silent. Silent too on
 * the controls S6 cannot see (altered policies, live snapshots), where no one ever creates the rows,
 * and where no package.json depends on Supabase. Points, coins and gems are reported at medium: in the
 * repositories read they were game currencies more often than paid ones.
 */
export const selfWritableEntitlementColumn: Rule = {
  id: "supabase.self-writable-entitlement-column",
  title: "Users can rewrite the credits, balance or plan the server trusts",
  description:
    "A column of the user's own row holds credits, a balance or a plan that the server decides on (a route refuses when credits run out, a SQL function or policy compares it), while an RLS policy lets that user update their row, or delete and re-insert it, without WITH CHECK, a column privilege or a trigger holding the column back. Any signed-up user gives themselves credits or a paid plan with one request to the Data API.",
  severity: "high",
  confidence: 0.7,
  cwe: ["CWE-863", "CWE-840"],
  evaluate(ctx) {
    if (ctx.model.supabaseClientAbsent) return [];
    const out: Finding[] = [];
    for (const src of entitlementSources(ctx).values()) {
      const t = ctx.model.tables.find((x) => x.table === src.table);
      if (!t || t.table.includes(".") || !t.rlsEnabled || t.location.file === SNAPSHOT_REF.file)
        continue;
      if (!t.columns.includes(src.column)) continue;
      if (!rowsGetCreated(ctx, t)) continue;
      const open = selfWritePath(t, src.column, ctx.model.sqlTriggers ?? []);
      if (open === null) continue;
      out.push(buildFinding(ctx, this, t, src, open));
    }
    return out;
  },
};

interface EntitlementSource {
  table: string;
  column: string;
  via: string[];
  refs: FileRef[];
  entries: string[];
}

/** Entitlement columns something on the server decides on, keyed `table.column`. */
function entitlementSources(ctx: RuleContext): Map<string, EntitlementSource> {
  const out = new Map<string, EntitlementSource>();
  const add = (table: string, column: string, via: string, ref: FileRef, entry?: string): void => {
    const key = `${table.toLowerCase()}.${column.toLowerCase()}`;
    const s: EntitlementSource = out.get(key) ?? {
      table: table.toLowerCase(),
      column: column.toLowerCase(),
      via: [],
      refs: [],
      entries: [],
    };
    if (!s.via.includes(via)) s.via.push(via);
    if (!s.refs.some((r) => r.file === ref.file && r.line === ref.line)) s.refs.push(ref);
    if (entry !== undefined && !s.entries.includes(entry)) s.entries.push(entry);
    out.set(key, s);
  };
  for (const route of ctx.model.routes) {
    for (const c of route.entitlementChecks ?? []) {
      if (!c.table || !c.column) continue;
      add(
        c.table,
        c.column,
        `the check "${c.text}" of ${route.entry} (${c.file}:${c.line})`,
        { file: c.file, line: c.line },
        route.entry,
      );
    }
  }
  for (const fn of sqlFunctionsOf(ctx.model)) {
    for (const c of fn.entitlementColumns ?? []) {
      add(
        c.table,
        c.column,
        `SQL function ${fn.name}() (${fn.location.file}:${fn.location.line})`,
        fn.location,
      );
    }
  }
  for (const t of ctx.model.tables) {
    for (const p of t.policyDetails) {
      for (const expr of [p.using, p.check]) {
        if (!expr) continue;
        for (const c of entitlementColumnsIn(`select ${expr}`)) {
          add(
            c.table,
            c.column,
            `policy "${p.name}" on ${t.table} (${p.location.file}:${p.location.line})`,
            p.location,
          );
        }
      }
    }
  }
  return out;
}

/** Names that usually hold an in-app game currency rather than something paid for: medium, not high. */
const GAME_CURRENCY = /^(?:points|gems|coins?|xp)$/i;

function buildFinding(
  ctx: RuleContext,
  rule: Rule,
  t: RlsTable,
  src: EntitlementSource,
  open: OpenPath,
): Finding {
  const col = `${t.table}.${src.column}`;
  const policyList = open.policies
    .map((p) => `"${p.name}" (${p.location.file}:${p.location.line})`)
    .join(" and ");
  const endpoint =
    open.how === "update" ? `PATCH /rest/v1/${t.table}` : `DELETE + POST /rest/v1/${t.table}`;
  const how =
    open.how === "update"
      ? `Policy ${policyList} lets a signed-in user update their own row of public.${t.table}, and neither its WITH CHECK nor a column privilege nor a BEFORE UPDATE trigger in the migrations holds ${src.column} back`
      : `The update path is closed, but ${policyList} let a signed-in user delete their own row of public.${t.table} and insert it again, and no BEFORE INSERT trigger or column privilege holds ${src.column} back`;
  const event = open.how === "update" ? "update" : "insert";
  const inert = (ctx.model.sqlTriggers ?? []).filter(
    (tr) => tr.inert && tr.table === t.table && tr.timing === "before" && tr.events.includes(event),
  );
  const inertNote =
    inert.length > 0
      ? ` Trigger ${inert.map((tr) => `${tr.name} (${tr.location.file}:${tr.location.line})`).join(" and ")} looks like a guard but does nothing: its function is SECURITY DEFINER and returns first unless current_user is a signed-in role, and inside SECURITY DEFINER current_user is the function's owner.`
      : "";
  const recursive = recursivePolicies(t);
  const recursionNote =
    recursive.length > 0
      ? ` Caveat: policy ${recursive.map((n) => `"${n}"`).join(" and ")} on public.${t.table} reads public.${t.table} itself, so as the migrations stand Postgres answers this request with "infinite recursion detected in policy" (42P17). A working application means the live policies differ: read them (select * from pg_policies where tablename = '${t.table}') before trusting or dismissing this finding.`
      : "";
  const path = [
    endpoint,
    `${open.how === "update" ? "set" : "re-insert with"} ${src.column} to any value on the caller's own row`,
    ...src.via.slice(0, 3).map((v) => `decided on by ${v}`),
  ];
  return {
    id: ctx.nextId(),
    ruleId: rule.id,
    status: recursive.length > 0 ? "candidate" : "likely",
    severity: GAME_CURRENCY.test(src.column) ? "medium" : rule.severity,
    confidence: recursive.length > 0 ? 0.5 : rule.confidence,
    cwe: rule.cwe,
    createdAt: ctx.now,
    updatedAt: ctx.now,
    title: `Signed-in users can rewrite "${col}", which the server trusts`,
    entrypoints: [endpoint, ...src.entries],
    sources: [`${event} body:${src.column}`],
    sinks: [`supabase.${event}:public.${t.table}`],
    path,
    evidence: [
      {
        kind: "rule",
        summary: `public.${col} holds what the user paid for or may spend, and the server decides on it: ${src.via.join("; ")}. ${how}, so any signed-up user gives themselves credits, a balance or a plan with one request to ${endpoint} using their own token.${inertNote}${recursionNote} Revoke UPDATE on the table from authenticated and grant back only the columns users may edit, or add WITH CHECK that keeps ${src.column} unchanged; change it only in the payment webhook (service role) or a SECURITY DEFINER function that checks the caller, and cover INSERT too if a trigger guards it.`,
        locations: locations(
          ...open.policies.map((p) => p.location),
          ...inert.map((tr) => tr.location),
          ...src.refs,
        ),
        data: {
          deterministic: false,
          ruleId: rule.id,
          table: t.table,
          column: src.column,
          path: open.how,
          policies: open.policies.map((p) => p.name),
          ...(recursive.length > 0 ? { recursivePolicies: recursive } : {}),
          ...(inert.length > 0 ? { inertTriggers: inert.map((tr) => tr.name) } : {}),
        },
      },
      { kind: "trace", summary: path.join(" -> ") },
    ],
  };
}

function locations(...refs: FileRef[]): FileRef[] {
  const out: FileRef[] = [];
  for (const r of refs) if (!out.some((o) => o.file === r.file && o.line === r.line)) out.push(r);
  return out;
}
