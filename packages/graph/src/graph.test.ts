import type { ProjectModel } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { buildGraph } from "./graph.js";

const model: ProjectModel = {
  root: "/x",
  files: [],
  routes: [
    {
      kind: "route",
      route: "/api/invoices/[id]",
      method: "GET",
      entry: "GET /api/invoices/[id]",
      location: { file: "app/api/invoices/[id]/route.ts", line: 7 },
      inputs: [
        {
          kind: "route_param",
          name: "id",
          location: { file: "app/api/invoices/[id]/route.ts", line: 13 },
        },
      ],
      authChecks: [{ file: "app/api/invoices/[id]/route.ts", line: 8 }],
      queries: [
        {
          table: "invoices",
          operation: "select",
          client: "service_role",
          clientName: "createServiceRoleClient",
          clientLocation: { file: "lib/supabase.ts", line: 7 },
          filters: [{ method: "eq", column: "id", valueText: "id", inputDerived: true }],
          payload: null,
          location: { file: "app/api/invoices/[id]/route.ts", line: 15 },
          text: "supabase.from('invoices').select('*').eq('id', id).single()",
        },
      ],
    },
  ],
  clientFactories: [],
  authHelpers: [],
  tables: [
    {
      table: "invoices",
      rlsEnabled: true,
      policies: ["tenant read"],
      location: { file: "m.sql", line: 1 },
    },
  ],
  warnings: [],
};

describe("buildGraph", () => {
  it("links route -> handler -> query -> client/table -> policy", () => {
    const g = buildGraph(model);
    const [route] = g.nodesOfKind("Route");
    const handler = g.out(route?.id ?? "", "HANDLES")[0];
    expect(handler?.kind).toBe("Handler");
    expect(g.out(handler?.id ?? "", "AUTHENTICATED_BY")).toHaveLength(1);
    expect(g.out(handler?.id ?? "", "READS").map((n) => n.label)).toEqual(["route_param:id"]);
    const query = g.out(handler?.id ?? "", "CALLS")[0];
    expect(g.out(query?.id ?? "", "USES_CLIENT")[0]?.data).toMatchObject({ kind: "service_role" });
    const table = g.out(query?.id ?? "", "TARGETS")[0];
    expect(table?.data).toMatchObject({ known: true, rlsEnabled: true });
    expect(g.out(table?.id ?? "", "GUARDED_BY").map((n) => n.label)).toEqual(["tenant read"]);
  });

  it("marks tables missing from migrations as unknown", () => {
    const g = buildGraph({ ...model, tables: [] });
    expect(g.nodesOfKind("Table")[0]?.data).toMatchObject({ known: false });
  });

  it("points storage calls at a bucket, not at a table", () => {
    const base = model.routes[0];
    if (!base) throw new Error("fixture model has no route");
    const g = buildGraph({
      ...model,
      routes: [
        {
          ...base,
          queries: [
            {
              table: "storage.objects",
              operation: "select",
              client: "service_role",
              clientName: "admin",
              clientLocation: null,
              filters: [],
              payload: null,
              location: { file: "app/api/files/route.ts", line: 9 },
              text: 'admin.storage.from("documents").download(path)',
              storage: {
                bucket: "documents",
                op: "download",
                pathText: "path",
                pathInputDerived: true,
                pathScopedToCaller: false,
              },
            },
          ],
        },
      ],
    });
    const query = g.nodesOfKind("Query")[0];
    expect(query?.data).toMatchObject({ storage: { bucket: "documents", op: "download" } });
    expect(g.out(query?.id ?? "", "TARGETS")).toEqual([]);
    expect(g.out(query?.id ?? "", "IN_BUCKET")[0]).toMatchObject({
      kind: "Bucket",
      data: { bucket: "documents" },
    });
  });

  it("keeps one query node per handler when two handlers reach the same helper query", () => {
    const base = model.routes[0];
    const q = base?.queries[0];
    const f0 = q?.filters[0];
    if (!base || !q || !f0) throw new Error("fixture model has no route");
    // The same helper line (lib/flows.ts:20) from two entry points: tainted in one, guarded in the other.
    const helperQuery = { ...q, location: { file: "lib/flows.ts", line: 20 } };
    const g = buildGraph({
      ...model,
      routes: [
        { ...base, queries: [{ ...helperQuery, filters: [{ ...f0, inputDerived: true }] }] },
        {
          ...base,
          entry: "DELETE /api/flows/[id]",
          method: "DELETE",
          location: { file: "app/api/flows/[id]/route.ts", line: 30 },
          queries: [
            {
              ...helperQuery,
              guard: {
                location: { file: "app/api/flows/[id]/route.ts", line: 35 },
                table: "invoices",
                client: "user_scoped",
                clientName: "supabase",
                filters: [],
                column: "id",
                exitsWhenMissing: true,
                text: "supabase.from('invoices').select('id').eq('id', id)",
              },
            },
          ],
        },
      ],
    });
    const queries = g.nodesOfKind("Query");
    expect(queries).toHaveLength(2);
    const [first, second] = g.nodesOfKind("Handler").map((h) => g.out(h.id, "CALLS")[0]?.data);
    expect(first).not.toHaveProperty("guard");
    expect(second).toMatchObject({ guard: { exitsWhenMissing: true } });
  });

  it("rejects edges to unknown nodes", () => {
    const g = buildGraph(model);
    expect(() => g.addEdge("nope", "nope2", "CALLS")).toThrow(/unknown node/);
  });
});
