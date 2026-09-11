import type {
  FileRef,
  MetadataAccess,
  PolicyDetail,
  ProjectModel,
  QueryFilter,
  QueryPayload,
} from "@auditai/parser";

export type NodeKind =
  | "Route"
  | "Handler"
  | "Source"
  | "AuthCheck"
  | "Client"
  | "Query"
  | "Table"
  | "RLSPolicy";
export type EdgeKind =
  | "HANDLES"
  | "READS"
  | "AUTHENTICATED_BY"
  | "CALLS"
  | "USES_CLIENT"
  | "TARGETS"
  | "GUARDED_BY";

export interface GraphNode {
  id: string;
  kind: NodeKind;
  label: string;
  data: Record<string, unknown>;
  location?: FileRef;
}

export interface GraphEdge {
  from: string;
  to: string;
  kind: EdgeKind;
}

/** Program Security Graph: routes, identities, clients, queries, tables and policies. See docs/ARCHITECTURE.md. */
export class SecurityGraph {
  readonly nodes = new Map<string, GraphNode>();
  readonly edges: GraphEdge[] = [];

  addNode(node: GraphNode): GraphNode {
    const existing = this.nodes.get(node.id);
    if (existing) return existing;
    this.nodes.set(node.id, node);
    return node;
  }

  addEdge(from: string, to: string, kind: EdgeKind): void {
    if (!this.nodes.has(from) || !this.nodes.has(to))
      throw new Error(`edge ${kind} references unknown node: ${from} -> ${to}`);
    if (!this.edges.some((e) => e.from === from && e.to === to && e.kind === kind))
      this.edges.push({ from, to, kind });
  }

  nodesOfKind(kind: NodeKind): GraphNode[] {
    return [...this.nodes.values()].filter((n) => n.kind === kind);
  }

  /** Targets of edges leaving `id`, optionally filtered by edge kind. */
  out(id: string, kind?: EdgeKind): GraphNode[] {
    return this.edges
      .filter((e) => e.from === id && (kind === undefined || e.kind === kind))
      .map((e) => this.nodes.get(e.to))
      .filter((n): n is GraphNode => n !== undefined);
  }

  /** Sources of edges entering `id`, optionally filtered by edge kind. */
  in(id: string, kind?: EdgeKind): GraphNode[] {
    return this.edges
      .filter((e) => e.to === id && (kind === undefined || e.kind === kind))
      .map((e) => this.nodes.get(e.from))
      .filter((n): n is GraphNode => n !== undefined);
  }
}

export interface QueryNodeData {
  operation: string;
  filters: QueryFilter[];
  payload: QueryPayload | null;
  text: string;
  table: string;
  /** Helper calls between the handler and the query, when the query lives outside the handler body. */
  via?: string[];
}

export interface HandlerNodeData {
  kind: string;
  entry: string;
  method: string;
  route: string;
  inputs: unknown[];
  metadataAccesses: MetadataAccess[];
}

export interface TableNodeData {
  table: string;
  /** False when the table was not seen in any migration; RLS state is then unknown. */
  known: boolean;
  rlsEnabled: boolean;
  policies: string[];
  policyDetails: PolicyDetail[];
  columns: string[];
}

export interface ClientNodeData {
  kind: string;
  name: string;
}

export function buildGraph(model: ProjectModel): SecurityGraph {
  const g = new SecurityGraph();
  const tableInfo = new Map(model.tables.map((t) => [t.table, t]));

  const tableNode = (table: string): GraphNode => {
    const info = tableInfo.get(table.toLowerCase());
    const data: TableNodeData = {
      table,
      known: info !== undefined,
      rlsEnabled: info?.rlsEnabled ?? false,
      policies: info?.policies ?? [],
      policyDetails: info?.policyDetails ?? [],
      columns: info?.columns ?? [],
    };
    const node = g.addNode(
      info
        ? {
            id: `table:${table}`,
            kind: "Table",
            label: `public.${table}`,
            data: { ...data },
            location: info.location,
          }
        : { id: `table:${table}`, kind: "Table", label: `public.${table}`, data: { ...data } },
    );
    for (const p of data.policies) {
      const pn = g.addNode({
        id: `policy:${table}:${p}`,
        kind: "RLSPolicy",
        label: p,
        data: { table, name: p },
      });
      g.addEdge(node.id, pn.id, "GUARDED_BY");
    }
    return node;
  };

  for (const h of model.routes) {
    const route = g.addNode({
      id: `route:${h.entry}`,
      kind: "Route",
      label: h.entry,
      data: { method: h.method, route: h.route, kind: h.kind },
    });
    const hd: HandlerNodeData = {
      kind: h.kind,
      entry: h.entry,
      method: h.method,
      route: h.route,
      inputs: h.inputs,
      metadataAccesses: h.metadataAccesses,
    };
    const handler = g.addNode({
      id: `handler:${h.location.file}:${h.location.line}`,
      kind: "Handler",
      label: `${h.entry} handler`,
      data: { ...hd },
      location: h.location,
    });
    g.addEdge(route.id, handler.id, "HANDLES");
    for (const i of h.inputs) {
      const s = g.addNode({
        id: `source:${handler.id}:${i.kind}:${i.name}`,
        kind: "Source",
        label: `${i.kind}:${i.name}`,
        data: { kind: i.kind, name: i.name },
        location: i.location,
      });
      g.addEdge(handler.id, s.id, "READS");
    }
    for (const a of h.authChecks) {
      const an = g.addNode({
        id: `auth:${a.file}:${a.line}`,
        kind: "AuthCheck",
        label: "auth check",
        data: {},
        location: a,
      });
      g.addEdge(handler.id, an.id, "AUTHENTICATED_BY");
    }
    h.queries.forEach((q, i) => {
      const qd: QueryNodeData = {
        operation: q.operation,
        filters: q.filters,
        payload: q.payload,
        text: q.text,
        table: q.table,
        ...(q.via && q.via.length > 0 ? { via: q.via } : {}),
      };
      const qn = g.addNode({
        id: `query:${q.location.file}:${q.location.line}:${i}`,
        kind: "Query",
        label: `${q.table}.${q.operation}`,
        data: { ...qd },
        location: q.location,
      });
      g.addEdge(handler.id, qn.id, "CALLS");
      const cd: ClientNodeData = { kind: q.client, name: q.clientName ?? "inline" };
      const cn = g.addNode(
        q.clientLocation
          ? {
              id: `client:${cd.name}:${cd.kind}`,
              kind: "Client",
              label: `${cd.name} (${cd.kind})`,
              data: { ...cd },
              location: q.clientLocation,
            }
          : {
              id: `client:${cd.name}:${cd.kind}`,
              kind: "Client",
              label: `${cd.name} (${cd.kind})`,
              data: { ...cd },
            },
      );
      g.addEdge(qn.id, cn.id, "USES_CLIENT");
      g.addEdge(qn.id, tableNode(q.table).id, "TARGETS");
    });
  }
  return g;
}
