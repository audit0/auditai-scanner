import type {
  AdminApiCall,
  FileRef,
  MetadataAccess,
  PolicyDetail,
  ProjectModel,
  QueryFilter,
  QueryGuard,
  QueryPayload,
  RoleCheck,
  StorageAccess,
} from "@auditai/parser";

export type NodeKind =
  | "Route"
  | "Handler"
  | "Source"
  | "AuthCheck"
  | "Client"
  | "Query"
  | "Table"
  | "RLSPolicy"
  | "Bucket";
export type EdgeKind =
  | "HANDLES"
  | "READS"
  | "AUTHENTICATED_BY"
  | "CALLS"
  | "USES_CLIENT"
  | "TARGETS"
  | "GUARDED_BY"
  | "IN_BUCKET";

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

/**
 * Program Security Graph: routes, identities, clients, queries, tables and policies. See
 * docs/ARCHITECTURE.md. Edges are indexed by both ends and nodes by kind, so building and walking the
 * graph stays linear in its size: a live snapshot turns every table into four Data API handlers, and a
 * lookup that scanned every edge made a 2,000-table snapshot take a minute.
 */
export class SecurityGraph {
  readonly nodes = new Map<string, GraphNode>();
  readonly edges: GraphEdge[] = [];
  private readonly edgeKeys = new Set<string>();
  private readonly outgoing = new Map<string, GraphEdge[]>();
  private readonly incoming = new Map<string, GraphEdge[]>();
  private readonly byKind = new Map<NodeKind, GraphNode[]>();

  addNode(node: GraphNode): GraphNode {
    const existing = this.nodes.get(node.id);
    if (existing) return existing;
    this.nodes.set(node.id, node);
    const same = this.byKind.get(node.kind);
    if (same) same.push(node);
    else this.byKind.set(node.kind, [node]);
    return node;
  }

  addEdge(from: string, to: string, kind: EdgeKind): void {
    if (!this.nodes.has(from) || !this.nodes.has(to))
      throw new Error(`edge ${kind} references unknown node: ${from} -> ${to}`);
    const key = `${from}\u0000${to}\u0000${kind}`;
    if (this.edgeKeys.has(key)) return;
    this.edgeKeys.add(key);
    const edge = { from, to, kind };
    this.edges.push(edge);
    SecurityGraph.index(this.outgoing, from, edge);
    SecurityGraph.index(this.incoming, to, edge);
  }

  private static index(map: Map<string, GraphEdge[]>, id: string, edge: GraphEdge): void {
    const list = map.get(id);
    if (list) list.push(edge);
    else map.set(id, [edge]);
  }

  nodesOfKind(kind: NodeKind): GraphNode[] {
    return [...(this.byKind.get(kind) ?? [])];
  }

  /** Targets of edges leaving `id`, optionally filtered by edge kind. */
  out(id: string, kind?: EdgeKind): GraphNode[] {
    return (this.outgoing.get(id) ?? [])
      .filter((e) => kind === undefined || e.kind === kind)
      .map((e) => this.nodes.get(e.to))
      .filter((n): n is GraphNode => n !== undefined);
  }

  /** Sources of edges entering `id`, optionally filtered by edge kind. */
  in(id: string, kind?: EdgeKind): GraphNode[] {
    return (this.incoming.get(id) ?? [])
      .filter((e) => kind === undefined || e.kind === kind)
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
  /** Supabase Storage call; such a query points at a Bucket node (IN_BUCKET) instead of a Table. */
  storage?: StorageAccess;
  /** An earlier read of the same row by the same id value, in this entry point. */
  guard?: QueryGuard;
  /** Comparisons of this read's own row made in code, each stopping the entry point. */
  ownerChecks?: QueryFilter[];
}

export interface BucketNodeData {
  /** Bucket id, or `(dynamic)` when the code does not name it with a literal. */
  bucket: string;
}

export interface HandlerNodeData {
  kind: string;
  entry: string;
  method: string;
  route: string;
  inputs: unknown[];
  metadataAccesses: MetadataAccess[];
  /** Role/claim predicates of the session that stop the handler (ADR-001). */
  roleChecks: RoleCheck[];
  /** Calls to the Auth admin API, which no policy constrains. Absent in older models. */
  adminApiCalls?: AdminApiCall[];
  /** The handler returns first thing in a production build: a development-only route. */
  productionExit?: FileRef;
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
      roleChecks: h.roleChecks ?? [],
      ...(h.adminApiCalls ? { adminApiCalls: h.adminApiCalls } : {}),
      ...(h.productionExit ? { productionExit: h.productionExit } : {}),
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
      const kind = a.kind ?? "session";
      const an = g.addNode({
        id: `auth:${a.file}:${a.line}:${kind}`,
        kind: "AuthCheck",
        label: `auth check (${kind})`,
        data: { kind, ...(a.method ? { method: a.method } : {}) },
        location: { file: a.file, line: a.line },
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
        ...(q.storage ? { storage: q.storage } : {}),
        ...(q.guard ? { guard: q.guard } : {}),
        ...(q.ownerChecks ? { ownerChecks: q.ownerChecks } : {}),
      };
      const qn = g.addNode({
        // Per handler: the same helper query reached from two entry points carries different
        // taint, filters and guards, so the nodes must not be shared.
        id: `query:${handler.id}:${q.location.file}:${q.location.line}:${i}`,
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
      if (q.storage) {
        // Storage objects are governed by storage.objects policies, not by the table rules of a public table.
        const bd: BucketNodeData = { bucket: q.storage.bucket ?? "(dynamic)" };
        const bn = g.addNode({
          id: `bucket:${bd.bucket}`,
          kind: "Bucket",
          label: `storage bucket ${bd.bucket}`,
          data: { ...bd },
        });
        g.addEdge(qn.id, bn.id, "IN_BUCKET");
      } else {
        g.addEdge(qn.id, tableNode(q.table).id, "TARGETS");
      }
    });
  }
  return g;
}
