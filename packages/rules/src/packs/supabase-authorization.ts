import type { Evidence, Finding } from "@auditai/core";
import type {
  ClientNodeData,
  GraphNode,
  HandlerNodeData,
  QueryNodeData,
  TableNodeData,
} from "@auditai/graph";
import type { FileRef, InputSource, QueryFilter } from "@auditai/parser";
import type { Rule, RuleContext } from "../rule.js";

const SCOPE_COLUMNS = new Set([
  "tenant_id",
  "org_id",
  "organization_id",
  "workspace_id",
  "team_id",
  "account_id",
  "company_id",
  "owner_id",
  "user_id",
  "created_by",
  "author_id",
  "profile_id",
]);

export function isScopeColumn(column: string | null): boolean {
  return column !== null && SCOPE_COLUMNS.has(column.toLowerCase());
}

export function isObjectIdColumn(column: string | null): boolean {
  if (column === null || isScopeColumn(column)) return false;
  const c = column.toLowerCase();
  return c === "id" || c === "uuid" || c === "slug" || c.endsWith("_id") || c.endsWith("id");
}

/** Does an RLS policy expression tie rows to the caller? */
export function policyScopesToCaller(expr: string | null): boolean {
  if (expr === null) return false;
  return /auth\.uid\(\)|auth\.jwt\(\)|current_setting\(|current_tenant|current_user_id|is_member|has_role|tenant_id|owner_id|user_id|created_by/i.test(
    expr,
  );
}

interface HandlerView {
  handler: GraphNode;
  data: HandlerNodeData;
  inputs: InputSource[];
  authenticated: boolean;
}

interface QueryView {
  query: GraphNode;
  data: QueryNodeData;
  client: GraphNode | undefined;
  clientData: ClientNodeData | undefined;
  table: GraphNode | undefined;
  tableData: TableNodeData | undefined;
}

function handlerViews(ctx: RuleContext): HandlerView[] {
  return ctx.graph.nodesOfKind("Handler").map((handler) => {
    const data = handler.data as unknown as HandlerNodeData;
    return {
      handler,
      data,
      inputs: (data.inputs as InputSource[] | undefined) ?? [],
      authenticated: ctx.graph.out(handler.id, "AUTHENTICATED_BY").length > 0,
    };
  });
}

function queryViews(ctx: RuleContext, handler: GraphNode): QueryView[] {
  return ctx.graph.out(handler.id, "CALLS").map((query) => {
    const client = ctx.graph.out(query.id, "USES_CLIENT")[0];
    const table = ctx.graph.out(query.id, "TARGETS")[0];
    return {
      query,
      data: query.data as unknown as QueryNodeData,
      client,
      clientData: client?.data as ClientNodeData | undefined,
      table,
      tableData: table?.data as TableNodeData | undefined,
    };
  });
}

function locations(...refs: Array<FileRef | undefined>): FileRef[] {
  return refs.filter((r): r is FileRef => r !== undefined);
}

/** Names the helper chain when the query does not sit in the handler body itself. */
function viaNote(q: QueryNodeData): string {
  return q.via && q.via.length > 0 ? ` Reached through ${q.via.join(" -> ")}.` : "";
}

function rlsNote(t: TableNodeData | undefined, tableName: string): string {
  if (!t?.known) return `public.${tableName} was not found in migrations; RLS state unknown.`;
  if (!t.rlsEnabled) return `RLS is disabled on public.${tableName}.`;
  return `RLS is enabled on public.${tableName} with ${t.policies.length} polic${t.policies.length === 1 ? "y" : "ies"}, but the service role bypasses it.`;
}

type Partial = Omit<
  Finding,
  "id" | "ruleId" | "status" | "severity" | "confidence" | "cwe" | "createdAt" | "updatedAt"
>;

function finding(ctx: RuleContext, rule: Rule, partial: Partial): Finding {
  return {
    id: ctx.nextId(),
    ruleId: rule.id,
    status: "likely",
    severity: rule.severity,
    confidence: rule.confidence,
    cwe: rule.cwe,
    createdAt: ctx.now,
    updatedAt: ctx.now,
    ...partial,
  };
}

function coveredByObjectAccessRule(q: QueryNodeData): boolean {
  const idFilter = q.filters.find((f) => f.inputDerived && isObjectIdColumn(f.column));
  return idFilter !== undefined && !q.filters.some((f) => isScopeColumn(f.column));
}

/**
 * R1. A handler reads/updates/deletes a row selected by a user-controlled identifier through a
 * service-role client (RLS bypassed) without scoping the query to the caller's tenant or ownership.
 * The classic AI-generated IDOR: authenticated, but not authorized.
 */
export const serviceRoleObjectAccessWithoutTenantScope: Rule = {
  id: "supabase.service-role-object-access-without-tenant-scope",
  title: "Object access via service-role client without tenant scope",
  description:
    "A query filtered by a user-controlled id runs with the service-role key, so Row Level Security does not apply, and nothing restricts the row to the caller's tenant or ownership.",
  severity: "critical",
  confidence: 0.85,
  cwe: ["CWE-639", "CWE-284"],
  evaluate(ctx) {
    const out: Finding[] = [];
    for (const h of handlerViews(ctx)) {
      for (const v of queryViews(ctx, h.handler)) {
        const q = v.data;
        if (v.clientData?.kind !== "service_role") continue;
        if (!["select", "update", "delete"].includes(q.operation)) continue;
        const filters: QueryFilter[] = q.filters;
        const idFilter = filters.find((f) => f.inputDerived && isObjectIdColumn(f.column));
        if (!idFilter || filters.some((f) => isScopeColumn(f.column))) continue;
        const tableName = v.tableData?.table ?? q.table;
        const authNote = h.authenticated
          ? "The handler authenticates the caller but never checks that the row belongs to them."
          : "The handler does not authenticate the caller at all.";
        const path = [
          h.data.kind === "server_action" ? "Server action call" : "HTTP request",
          h.data.entry,
          `${idFilter.column} ${idFilter.method} ${idFilter.valueText} (user-controlled)`,
          `${v.clientData.name} (service role, bypasses RLS)`,
          `public.${tableName}.${q.operation}`,
        ];
        const evidence: Evidence[] = [
          {
            kind: "rule",
            summary: `${q.operation} on public.${tableName} filtered by user-controlled "${idFilter.column}" through a service-role client, with no tenant/owner scoping. ${authNote} ${rlsNote(v.tableData, tableName)}${viaNote(q)}`,
            locations: locations(h.handler.location, v.query.location, v.client?.location),
            data: {
              deterministic: false,
              ruleId: this.id,
              authenticated: h.authenticated,
              query: q.text,
            },
          },
          { kind: "trace", summary: path.join(" -> ") },
        ];
        out.push(
          finding(ctx, this, {
            title: `${h.authenticated ? "Cross-tenant" : "Unauthenticated"} ${q.operation} on "${tableName}" via service-role client`,
            entrypoints: [h.data.entry],
            sources: h.inputs.map((i) => `${i.kind}:${i.name}`),
            sinks: [`supabase.${q.operation}:public.${tableName}`],
            path,
            evidence,
          }),
        );
      }
    }
    return out;
  },
};

/** R2. A user-facing client (anon or user-scoped) queries a table that has RLS disabled: every row is readable. */
export const tableWithoutRls: Rule = {
  id: "supabase.table-without-rls",
  title: "Table queried by a user-facing client has RLS disabled",
  description:
    "Queries made with the anon key run as the caller against PostgREST. Without Row Level Security the table is fully exposed to anyone with the public key.",
  severity: "high",
  confidence: 0.9,
  cwe: ["CWE-284", "CWE-862"],
  evaluate(ctx) {
    // One finding per table: the defect is the missing RLS, every handler that reaches it is evidence.
    const groups = new Map<string, Group>();
    for (const h of handlerViews(ctx)) {
      for (const v of queryViews(ctx, h.handler)) {
        const c = v.clientData;
        if (c?.kind !== "anon" && c?.kind !== "user_scoped") continue;
        const t = v.tableData;
        if (!t?.known || t.rlsEnabled) continue;
        const g = group(groups, t.table, () => ({
          path: [
            "HTTP request",
            h.data.entry,
            `${c.name} (${c.kind}, RLS would apply)`,
            `public.${t.table} (RLS disabled)`,
          ],
          summary: `public.${t.table} has no "enable row level security" in migrations but is queried with a ${c.kind} client. Anyone holding the public anon key can read every row directly through PostgREST.`,
          title: `Table "${t.table}" is exposed without RLS`,
          data: { deterministic: true, ruleId: this.id },
          tail: locations(v.table?.location),
        }));
        addReach(g, h, v, `supabase.${v.data.operation}:public.${t.table}`);
      }
    }
    return emitGroups(ctx, this, groups);
  },
};

/** Accumulates every handler that reaches one defective table or policy into a single finding. */
interface Group {
  title: string;
  path: string[];
  summary: string;
  data: Record<string, unknown>;
  entrypoints: string[];
  sources: Set<string>;
  sinks: Set<string>;
  queryLocations: FileRef[];
  tail: FileRef[];
}

function group(
  groups: Map<string, Group>,
  key: string,
  init: () => Pick<Group, "title" | "path" | "summary" | "data" | "tail">,
): Group {
  let g = groups.get(key);
  if (!g) {
    g = { ...init(), entrypoints: [], sources: new Set(), sinks: new Set(), queryLocations: [] };
    groups.set(key, g);
  }
  return g;
}

function addReach(g: Group, h: HandlerView, v: QueryView, sink: string): void {
  if (!g.entrypoints.includes(h.data.entry)) g.entrypoints.push(h.data.entry);
  for (const i of h.inputs) g.sources.add(`${i.kind}:${i.name}`);
  g.sinks.add(sink);
  if (v.query.location && !g.queryLocations.some((l) => sameRef(l, v.query.location))) {
    g.queryLocations.push(v.query.location);
  }
}

function sameRef(a: FileRef, b: FileRef | undefined): boolean {
  return b !== undefined && a.file === b.file && a.line === b.line;
}

function emitGroups(ctx: RuleContext, rule: Rule, groups: Map<string, Group>): Finding[] {
  const out: Finding[] = [];
  for (const g of groups.values()) {
    const reached =
      g.entrypoints.length > 1 ? ` Reached from ${g.entrypoints.length} entry points.` : "";
    out.push(
      finding(ctx, rule, {
        title: g.title,
        entrypoints: g.entrypoints,
        sources: [...g.sources],
        sinks: [...g.sinks],
        path: g.path,
        evidence: [
          {
            kind: "rule",
            summary: g.summary + reached,
            locations: [...g.queryLocations, ...g.tail],
            data: g.data,
          },
          { kind: "trace", summary: g.path.join(" -> ") },
        ],
      }),
    );
  }
  return out;
}

/** R3. RLS is on, but a policy grants rows without tying them to the caller (e.g. `using (true)`). */
export const rlsPolicyWithoutCallerPredicate: Rule = {
  id: "supabase.rls-policy-without-caller-predicate",
  title: "RLS policy grants rows without a caller predicate",
  description:
    "A policy such as `using (true)` or one that never references auth.uid()/tenant makes RLS a no-op for that command: every authenticated user sees every row.",
  severity: "high",
  confidence: 0.85,
  cwe: ["CWE-863", "CWE-284"],
  evaluate(ctx) {
    // One finding per (table, policy): the defect is the policy, every handler that reaches it is evidence.
    const groups = new Map<string, Group>();
    for (const h of handlerViews(ctx)) {
      for (const v of queryViews(ctx, h.handler)) {
        const c = v.clientData;
        const t = v.tableData;
        if (c?.kind !== "anon" && c?.kind !== "user_scoped") continue;
        if (!t?.known || !t.rlsEnabled) continue;
        if (!t.columns.some((col) => isScopeColumn(col))) continue;
        const op = v.data.operation === "unknown" ? "select" : v.data.operation;
        for (const p of t.policyDetails) {
          if (p.command !== "all" && p.command !== op) continue;
          const expr = op === "insert" ? p.check : p.using;
          if (expr === null || policyScopesToCaller(expr)) continue;
          const g = group(groups, `${t.table}:${p.name}:${p.command}`, () => ({
            path: [
              "HTTP request",
              h.data.entry,
              `${c.name} (${c.kind})`,
              `public.${t.table} policy "${p.name}" ${op === "insert" ? "with check" : "using"} (${expr})`,
            ],
            summary: `Policy "${p.name}" for ${p.command} on public.${t.table} uses (${expr}). The table has a scope column (${t.columns.filter(isScopeColumn).join(", ")}) but the policy never compares it to auth.uid() or the caller's tenant, so RLS lets every ${p.roles.join("/") || "authenticated"} user through.`,
            title: `RLS policy "${p.name}" on "${t.table}" does not scope rows to the caller`,
            data: { deterministic: false, ruleId: this.id, policy: p.name },
            tail: locations(p.location),
          }));
          addReach(g, h, v, `supabase.${op}:public.${t.table}`);
        }
      }
    }
    return emitGroups(ctx, this, groups);
  },
};

/** R4. The tenant/owner scope of a service-role query is taken from the request instead of the session. */
export const userControlledTenantScope: Rule = {
  id: "supabase.user-controlled-tenant-scope",
  title: "Tenant scope taken from the request",
  description:
    "The query is scoped by a tenant/owner column, but the value comes from user input. An attacker supplies another tenant's id and the service-role client happily returns its rows.",
  severity: "critical",
  confidence: 0.85,
  cwe: ["CWE-639", "CWE-566"],
  evaluate(ctx) {
    const out: Finding[] = [];
    for (const h of handlerViews(ctx)) {
      for (const v of queryViews(ctx, h.handler)) {
        if (v.clientData?.kind !== "service_role") continue;
        const scope = v.data.filters.find((f) => isScopeColumn(f.column) && f.inputDerived);
        if (!scope) continue;
        const tableName = v.tableData?.table ?? v.data.table;
        const path = [
          "HTTP request",
          h.data.entry,
          `${scope.column} ${scope.method} ${scope.valueText} (user-controlled)`,
          `${v.clientData.name} (service role, bypasses RLS)`,
          `public.${tableName}.${v.data.operation}`,
        ];
        out.push(
          finding(ctx, this, {
            title: `Tenant scope for "${tableName}" comes from the request`,
            entrypoints: [h.data.entry],
            sources: h.inputs.map((i) => `${i.kind}:${i.name}`),
            sinks: [`supabase.${v.data.operation}:public.${tableName}`],
            path,
            evidence: [
              {
                kind: "rule",
                summary: `${v.data.operation} on public.${tableName} is filtered by "${scope.column}" = ${scope.valueText}, which the caller controls. The tenant must come from the authenticated session (profile lookup or JWT claim), never from the request. ${rlsNote(v.tableData, tableName)}`,
                locations: locations(h.handler.location, v.query.location, v.client?.location),
                data: { deterministic: false, ruleId: this.id, authenticated: h.authenticated },
              },
              { kind: "trace", summary: path.join(" -> ") },
            ],
          }),
        );
      }
    }
    return out;
  },
};

/** R5. Authorization decided by user_metadata, which the end user can edit through supabase.auth.updateUser(). */
export const roleFromUserMetadata: Rule = {
  id: "supabase.role-check-from-user-metadata",
  title: "Authorization based on user-editable metadata",
  description:
    "user.user_metadata is writable by the user themselves via updateUser(). Roles and flags must live in app_metadata or a server-controlled table.",
  severity: "high",
  confidence: 0.85,
  cwe: ["CWE-602", "CWE-863"],
  evaluate(ctx) {
    const out: Finding[] = [];
    for (const h of handlerViews(ctx)) {
      const hits = h.data.metadataAccesses.filter(
        (m) =>
          m.bucket === "user_metadata" && /role|admin|permission|plan|tier|scope|is_/i.test(m.path),
      );
      const first = hits[0];
      if (!first) continue;
      const path = [
        "HTTP request",
        h.data.entry,
        `${first.path} (end-user editable)`,
        "authorization decision",
      ];
      out.push(
        finding(ctx, this, {
          title: `Role check reads user_metadata in ${h.data.entry}`,
          entrypoints: [h.data.entry],
          sources: ["auth.user_metadata (editable by the user)"],
          sinks: [h.data.entry],
          path,
          evidence: [
            {
              kind: "rule",
              summary: `${hits.map((m) => m.path).join(", ")} is read from user_metadata, which any signed-in user can change with supabase.auth.updateUser({ data: { role: "admin" } }). Use app_metadata (service-role only) or a profiles.role column.`,
              locations: locations(h.handler.location, ...hits.map((m) => m.location)),
              data: { deterministic: false, ruleId: this.id },
            },
            { kind: "trace", summary: path.join(" -> ") },
          ],
        }),
      );
    }
    return out;
  },
};

/** R6. Service-role key reaches the browser: NEXT_PUBLIC_ env or a "use client" component. Deterministic, blocking. */
export const serviceRoleKeyExposedToClient: Rule = {
  id: "supabase.service-role-key-exposed-to-client",
  title: "Service-role key shipped to the browser",
  description:
    "The service-role key bypasses RLS entirely. Anything in a NEXT_PUBLIC_ variable or a client component is downloadable by every visitor.",
  severity: "critical",
  confidence: 1,
  cwe: ["CWE-798", "CWE-200"],
  evaluate(ctx) {
    return ctx.model.exposures.map((x) =>
      finding(ctx, this, {
        title:
          x.kind === "public_env_service_role"
            ? `Service-role key in a NEXT_PUBLIC_ variable (${x.location.file})`
            : `Service-role client inside a client component (${x.location.file})`,
        entrypoints: [x.location.file],
        sources: ["browser bundle"],
        sinks: ["supabase service role"],
        path: [
          "browser bundle",
          x.location.file,
          "service-role key",
          "full database access, RLS bypassed",
        ],
        evidence: [
          {
            kind: "rule",
            summary: x.evidence,
            locations: [x.location],
            data: { deterministic: true, ruleId: this.id, exposure: x.kind },
          },
          {
            kind: "trace",
            summary: `browser bundle -> ${x.location.file}:${x.location.line} -> service-role key`,
          },
        ],
      }),
    );
  },
};

/** R7. A service-role query runs in a handler that never authenticates the caller. */
export const serviceRoleQueryWithoutAuthentication: Rule = {
  id: "supabase.service-role-query-without-authentication",
  title: "Service-role query in an unauthenticated handler",
  description:
    "The handler performs privileged database access with the service-role key but never establishes who is calling. Anyone on the internet can invoke it.",
  severity: "critical",
  confidence: 0.8,
  cwe: ["CWE-306", "CWE-284"],
  evaluate(ctx) {
    const out: Finding[] = [];
    for (const h of handlerViews(ctx)) {
      if (h.authenticated) continue;
      const views = queryViews(ctx, h.handler).filter(
        (v) => v.clientData?.kind === "service_role" && !coveredByObjectAccessRule(v.data),
      );
      const v = views[0];
      if (!v) continue;
      const tables = [...new Set(views.map((x) => x.tableData?.table ?? x.data.table))];
      const path = [
        h.data.kind === "server_action" ? "Server action call" : "HTTP request",
        h.data.entry,
        "no authentication",
        `${v.clientData?.name ?? "client"} (service role, bypasses RLS)`,
        `public.${tables.join(", public.")}`,
      ];
      out.push(
        finding(ctx, this, {
          title: `Unauthenticated service-role access to "${tables.join('", "')}" in ${h.data.entry}`,
          entrypoints: [h.data.entry],
          sources: h.inputs.map((i) => `${i.kind}:${i.name}`),
          sinks: views.map(
            (x) => `supabase.${x.data.operation}:public.${x.tableData?.table ?? x.data.table}`,
          ),
          path,
          evidence: [
            {
              kind: "rule",
              summary: `${h.data.entry} runs ${views.length} service-role quer${views.length === 1 ? "y" : "ies"} (${tables.join(", ")}) and contains no auth.getUser/getSession/getClaims call or auth helper. If this is a webhook or cron endpoint, it needs signature verification, which was not detected either.`,
              locations: locations(h.handler.location, ...views.map((x) => x.query.location)),
              data: { deterministic: false, ruleId: this.id },
            },
            { kind: "trace", summary: path.join(" -> ") },
          ],
        }),
      );
    }
    return out;
  },
};

/** R8. The whole request body is written to a table: the caller can set any column (role, tenant_id, price...). */
export const massAssignmentFromRequestBody: Rule = {
  id: "supabase.mass-assignment-from-request-body",
  title: "Request body written to a table without an allow-list",
  description:
    "insert/update/upsert receives the parsed request body as-is. Any column the caller names gets written, including role, tenant_id or owner_id.",
  severity: "high",
  confidence: 0.85,
  cwe: ["CWE-915"],
  evaluate(ctx) {
    const out: Finding[] = [];
    for (const h of handlerViews(ctx)) {
      for (const v of queryViews(ctx, h.handler)) {
        const p = v.data.payload;
        if (!p?.wholeInput) continue;
        const tableName = v.tableData?.table ?? v.data.table;
        const cols = v.tableData?.columns ?? [];
        const sensitive = cols.filter(
          (c) => isScopeColumn(c) || /role|admin|price|amount|status|plan|tier|balance/i.test(c),
        );
        const path = [
          "HTTP request",
          h.data.entry,
          `${p.text} (entire request input)`,
          `${v.clientData?.name ?? "client"} (${v.clientData?.kind ?? "unknown"})`,
          `public.${tableName}.${v.data.operation}`,
        ];
        out.push(
          finding(ctx, this, {
            title: `Mass assignment into "${tableName}" from the request body`,
            entrypoints: [h.data.entry],
            sources: h.inputs.map((i) => `${i.kind}:${i.name}`),
            sinks: [`supabase.${v.data.operation}:public.${tableName}`],
            path,
            evidence: [
              {
                kind: "rule",
                summary: `${v.data.operation} on public.${tableName} writes ${p.text} directly. ${sensitive.length > 0 ? `Columns the caller could set: ${sensitive.join(", ")}.` : "Every column of the table is writable by the caller."} Pick the allowed fields explicitly.`,
                locations: locations(h.handler.location, v.query.location),
                data: { deterministic: false, ruleId: this.id, payload: p.text },
              },
              { kind: "trace", summary: path.join(" -> ") },
            ],
          }),
        );
      }
    }
    return out;
  },
};

export const supabaseAuthorizationPack: readonly Rule[] = [
  serviceRoleKeyExposedToClient,
  serviceRoleObjectAccessWithoutTenantScope,
  userControlledTenantScope,
  serviceRoleQueryWithoutAuthentication,
  massAssignmentFromRequestBody,
  roleFromUserMetadata,
  tableWithoutRls,
  rlsPolicyWithoutCallerPredicate,
];
