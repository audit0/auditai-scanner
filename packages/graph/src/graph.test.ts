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

  it("rejects edges to unknown nodes", () => {
    const g = buildGraph(model);
    expect(() => g.addEdge("nope", "nope2", "CALLS")).toThrow(/unknown node/);
  });
});
