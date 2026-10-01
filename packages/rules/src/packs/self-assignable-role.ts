import type { Finding } from "@auditai/core";
import {
  type FileRef,
  type PolicyDetail,
  type RlsTable,
  ROLE_COLUMN,
  recursivePolicies,
  roleColumnsIn,
  SNAPSHOT_REF,
  type SqlTrigger,
} from "@auditai/parser";
import type { Rule, RuleContext } from "../rule.js";
import { sqlFunctionsOf } from "./sql-functions.js";

/**
 * S6. A column of the caller's own row decides a privilege (a role check in a route or server
 * action, an `is_admin()`-style SQL helper, or a policy that reads it), and the same user may rewrite
 * that column through the Data API: a permissive UPDATE (or ALL) policy on their own row whose
 * WITH CHECK leaves the column free, no column privilege keeps them out, and no BEFORE UPDATE
 * trigger holds the column back. Or, with the update path closed, they may delete their row and
 * insert it again under INSERT and DELETE policies no BEFORE INSERT trigger watches.
 *
 * Silent where it cannot see the controls: a policy an ALTER POLICY changed is not concluded from,
 * a WITH CHECK or restrictive policy that names the column counts as holding it, and a live snapshot
 * (which carries no triggers) is not judged at all. Silent too where the user never has a row to
 * rewrite (nothing inserts into the table: no function, no INSERT policy, no service-role insert in
 * the app), and where no package.json depends on Supabase (the SQL is left over from another stack).
 */
export const selfAssignableRoleColumn: Rule = {
  id: "supabase.self-assignable-role-column",
  title: "Users can rewrite the role column that grants their privileges",
  description:
    "A column of the user's own row decides a privilege (an admin check in code, an is_admin() SQL helper or a policy), while an RLS policy lets that user update their row, or delete and re-insert it, without WITH CHECK, a column privilege or a trigger holding the column back. Any signed-up user sets it to admin with one request to the Data API.",
  severity: "critical",
  confidence: 0.8,
  cwe: ["CWE-269", "CWE-863"],
  evaluate(ctx) {
    if (ctx.model.supabaseClientAbsent) return [];
    const sources = privilegeSources(ctx);
    const out: Finding[] = [];
    for (const src of sources.values()) {
      const t = ctx.model.tables.find((x) => x.table === src.table);
      // Other schemas are not exposed through the Data API by default.
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

/**
 * Something puts rows in the table: a SQL function that writes it (a sign-up trigger, an RPC, a
 * trigger on another table), a permissive INSERT policy for signed-in users, or an insert or upsert
 * from the app through the service role, a direct database connection or a client the parser could
 * not resolve. With none of these no user
 * ever owns a row there (Battalion-Store, liberia-chinese in the sixth blind sample).
 */
export function rowsGetCreated(ctx: RuleContext, t: RlsTable): boolean {
  if (sqlFunctionsOf(ctx.model).some((f) => (f.writes ?? []).includes(t.table))) return true;
  if (
    t.policyDetails.some(
      (p) =>
        p.permissive !== false &&
        appliesToSignedIn(p) &&
        (p.command === "insert" || p.command === "all"),
    )
  )
    return true;
  return ctx.model.routes.some((r) =>
    r.queries.some(
      (q) =>
        q.table === t.table &&
        (q.operation === "insert" || q.operation === "upsert") &&
        // A user-scoped insert needs an INSERT policy, counted above; an unresolved client may be the
        // service role (DayFlow's `createClient as createAdminClient`).
        q.client !== "anon" &&
        q.client !== "user_scoped",
    ),
  );
}

export interface PrivilegeSource {
  table: string;
  column: string;
  /** Where the column decides a privilege, for evidence. */
  via: string[];
  refs: FileRef[];
  entries: string[];
}

/** Columns of the caller's own row that decide a privilege, keyed `table.column`. */
export function privilegeSources(ctx: RuleContext): Map<string, PrivilegeSource> {
  const out = new Map<string, PrivilegeSource>();
  const add = (table: string, column: string, via: string, ref: FileRef, entry?: string): void => {
    const key = `${table.toLowerCase()}.${column.toLowerCase()}`;
    const s: PrivilegeSource = out.get(key) ?? {
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
    for (const rc of route.roleChecks ?? []) {
      // A gate may compare any column of the caller's row (an org id, a name); only a role counts here.
      if (!rc.table || !rc.column || !CODE_ROLE_COLUMN.test(rc.column)) continue;
      add(
        rc.table,
        rc.column,
        `the role check of ${route.entry} (${rc.file}:${rc.line})`,
        { file: rc.file, line: rc.line },
        route.entry,
      );
    }
  }
  for (const fn of sqlFunctionsOf(ctx.model)) {
    for (const rc of fn.roleColumns ?? []) {
      add(
        rc.table,
        rc.column,
        `SQL function ${fn.name}() (${fn.location.file}:${fn.location.line})`,
        fn.location,
      );
    }
  }
  for (const t of ctx.model.tables) {
    for (const p of t.policyDetails) {
      for (const expr of [p.using, p.check]) {
        if (!expr) continue;
        for (const rc of roleColumnsIn(`select ${expr}`)) {
          add(
            rc.table,
            rc.column,
            `policy "${p.name}" on ${t.table} (${p.location.file}:${p.location.line})`,
            p.location,
          );
        }
      }
    }
  }
  return out;
}

export interface OpenPath {
  how: "update" | "reinsert";
  policies: PolicyDetail[];
}

/** Role-named columns, plus the type lists some projects keep roles in (`user_types`, `account_type`). */
const CODE_ROLE_COLUMN = new RegExp(
  `${ROLE_COLUMN.source}|^(?:user_?types?|account_?types?|user_?kind|member_?role)$`,
  "i",
);

const IDENTITY = String.raw`\(?\s*(?:select\s+)?auth\s*\.\s*(?:uid|email)\s*\(\s*\)\s*\)?(?:\s*::\s*\w+)?`;
const COLUMN = String.raw`(?:"?[A-Za-z_][\w$]*"?\s*\.\s*)?"?[A-Za-z_][\w$]*"?(?:\s*::\s*\w+)?`;
const DIRECT = new RegExp(`${COLUMN}\\s*=\\s*${IDENTITY}|${IDENTITY}\\s*=\\s*${COLUMN}`, "i");

/**
 * The expression ties the row itself to the caller: a column of the row compared with auth.uid()
 * (or auth.email()), outside any subquery. `exists (select 1 from profiles where id = auth.uid() and
 * ...)` is a check about someone else's row, not this one.
 */
function ownRow(expr: string | null): boolean {
  if (expr === null) return false;
  return DIRECT.test(withoutSubqueries(expr));
}

/** `(select ...)` groups replaced by `(true)`, except `(select auth.uid())`, which is the identity itself. */
function withoutSubqueries(expr: string): string {
  let out = "";
  let i = 0;
  while (i < expr.length) {
    const open = /\(\s*select\b/iy;
    open.lastIndex = i;
    if (expr[i] === "(" && open.test(expr)) {
      let depth = 0;
      let j = i;
      for (; j < expr.length; j += 1) {
        if (expr[j] === "(") depth += 1;
        else if (expr[j] === ")") {
          depth -= 1;
          if (depth === 0) break;
        }
      }
      const group = expr.slice(i, j + 1);
      out += /^\(\s*select\s+auth\s*\.\s*(?:uid|email)\s*\(\s*\)\s*\)$/i.test(group)
        ? group
        : "(true)";
      i = j + 1;
    } else {
      out += expr[i];
      i += 1;
    }
  }
  return out;
}

function appliesToSignedIn(p: PolicyDetail): boolean {
  return p.roles.length === 0 || p.roles.some((r) => r === "authenticated" || r === "public");
}

function mentions(expr: string | null, column: string): boolean {
  if (expr === null) return false;
  return new RegExp(`(?<![A-Za-z0-9_$])"?${column}"?(?![A-Za-z0-9_$])`, "i").test(expr);
}

/**
 * How the owner of a row may set `column` on it, or null when something holds it back. For UPDATE,
 * Postgres checks the new row with WITH CHECK, or with USING when there is none.
 */
export function selfWritePath(
  t: RlsTable,
  column: string,
  triggers: readonly SqlTrigger[],
): OpenPath | null {
  const altered = new Set(t.alteredPolicies ?? []);
  const usable = (p: PolicyDetail): boolean =>
    p.permissive !== false && appliesToSignedIn(p) && !altered.has(p.name.toLowerCase());
  const restrictiveHolds = t.policyDetails.some(
    (p) => p.permissive === false && (mentions(p.check, column) || mentions(p.using, column)),
  );
  if (restrictiveHolds) return null;
  const guarded = (event: "update" | "insert"): boolean =>
    triggers.some(
      (tr) =>
        tr.table === t.table &&
        tr.timing === "before" &&
        tr.events.includes(event) &&
        tr.checkedColumns.includes(column),
    );
  const can = (kind: "update" | "insert"): boolean => {
    const cols = t.authenticatedWrites?.[kind];
    return cols === undefined || cols.includes(column);
  };
  // The Data API changes only rows the caller can read.
  // An altered policy still exists; only its exact condition is unknown, which is enough here.
  const readable = t.policyDetails.some(
    (p) =>
      p.permissive !== false &&
      appliesToSignedIn(p) &&
      (p.command === "select" || p.command === "all"),
  );
  if (!readable) return null;

  const update = t.policyDetails.find(
    (p) =>
      usable(p) &&
      (p.command === "update" || p.command === "all") &&
      ownRow(p.using) &&
      !mentions(p.check ?? p.using, column),
  );
  if (update && can("update") && !guarded("update")) return { how: "update", policies: [update] };

  const insert = t.policyDetails.find(
    (p) =>
      usable(p) &&
      (p.command === "insert" || p.command === "all") &&
      ownRow(p.check ?? p.using) &&
      !mentions(p.check ?? p.using, column),
  );
  const del = t.policyDetails.find(
    (p) => usable(p) && (p.command === "delete" || p.command === "all") && ownRow(p.using),
  );
  if (insert && del && can("insert") && !guarded("insert")) {
    return { how: "reinsert", policies: insert === del ? [insert] : [del, insert] };
  }
  return null;
}

function buildFinding(
  ctx: RuleContext,
  rule: Rule,
  t: RlsTable,
  src: PrivilegeSource,
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
      ? ` Trigger ${inert.map((tr) => `${tr.name} (${tr.location.file}:${tr.location.line})`).join(" and ")} looks like a guard but does nothing: its function is SECURITY DEFINER and returns first unless current_user is a signed-in role, and inside SECURITY DEFINER current_user is the function's owner. Drop SECURITY DEFINER from it or test auth.role() instead.`
      : "";
  // As the migrations stand, a SELECT policy that reads its own table makes every filtered write fail
  // with 42P17, and Supabase refuses unfiltered ones: the live policies must differ. The missing
  // WITH CHECK most likely survives there, but the finding cannot say so from the files.
  const recursive = recursivePolicies(t);
  const recursionNote =
    recursive.length > 0
      ? ` Caveat: policy ${recursive.map((n) => `"${n}"`).join(" and ")} on public.${t.table} reads public.${t.table} itself, so as the migrations stand Postgres answers this request, and every check that reads the table under RLS, with "infinite recursion detected in policy" (42P17). A working application means the live policies differ: read them (select * from pg_policies where tablename = '${t.table}') before trusting or dismissing this finding.`
      : "";
  const path = [
    endpoint,
    `${open.how === "update" ? "set" : "re-insert with"} ${src.column} = 'admin' on the caller's own row`,
    ...src.via.slice(0, 3).map((v) => `read as a privilege by ${v}`),
  ];
  return {
    id: ctx.nextId(),
    ruleId: rule.id,
    status: recursive.length > 0 ? "candidate" : "likely",
    severity: rule.severity,
    confidence: recursive.length > 0 ? 0.5 : rule.confidence,
    cwe: rule.cwe,
    createdAt: ctx.now,
    updatedAt: ctx.now,
    title: `Signed-in users can rewrite "${col}", which grants privileges`,
    entrypoints: [endpoint, ...src.entries],
    sources: [`${open.how === "update" ? "update" : "insert"} body:${src.column}`],
    sinks: [`supabase.${open.how === "update" ? "update" : "insert"}:public.${t.table}`],
    path,
    evidence: [
      {
        kind: "rule",
        summary: `public.${col} decides a privilege: it is read by ${src.via.join("; ")}. ${how}, so any signed-up user sets it to an admin value with one request to ${endpoint} using their own token, and passes every check that reads it.${inertNote}${recursionNote} Add WITH CHECK that keeps ${src.column} unchanged, revoke UPDATE on the table from authenticated and grant back only the columns users may edit, or keep roles in a table or app_metadata only the server writes; a trigger must cover INSERT as well as UPDATE.`,
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
