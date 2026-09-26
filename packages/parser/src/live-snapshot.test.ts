import { describe, expect, it } from "vitest";
import { parseLiveSnapshot, SNAPSHOT_REF } from "./live-snapshot.js";

/**
 * The snapshot reader turns what a live database reports into the facts the SQL rules already read
 * from migrations (docs/realworld/2026-09-20-schema-truth.md). Nothing here is inferred: every
 * assertion below is a value Postgres itself returned.
 */

const snapshot = (over: Record<string, unknown> = {}): string =>
  JSON.stringify({
    snapshotVersion: 1,
    takenAt: "2026-09-20T09:00:00Z",
    postgres: "17.11",
    tables: [],
    policies: [],
    functions: [],
    buckets: [],
    ...over,
  });

/** What Supabase grants on every new table in public: all four privileges to both API roles. */
const SUPABASE_GRANTS = ["SELECT", "INSERT", "UPDATE", "DELETE"].flatMap((privilege) => [
  { grantee: "anon", privilege },
  { grantee: "authenticated", privilege },
]);

const table = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  schema: "public",
  name: "notes",
  rlsEnabled: true,
  kind: "table",
  columns: [],
  grants: SUPABASE_GRANTS,
  ...over,
});

const ok = (text: string) => {
  const r = parseLiveSnapshot(text);
  if (!r.ok) throw new Error(`expected a snapshot, got: ${r.error}`);
  return r.model;
};

describe("parseLiveSnapshot", () => {
  it("refuses anything that is not a snapshot it understands", () => {
    for (const [text, part] of [
      ["not json at all", "not JSON"],
      ["[1,2]", "not an object"],
      [JSON.stringify({ snapshotVersion: 2, tables: [], policies: [] }), "snapshotVersion"],
      [JSON.stringify({ snapshotVersion: 1 }), "no tables or policies"],
    ] as const) {
      const r = parseLiveSnapshot(text);
      expect(r.ok, text).toBe(false);
      if (!r.ok) expect(r.error).toContain(part);
    }
  });

  it("keys tables the way the rules do and keeps the column facts a seed needs", () => {
    const m = ok(
      snapshot({
        tables: [
          table({
            columns: [
              { name: "id", type: "uuid", notNull: true, hasDefault: true, references: null },
              {
                name: "ownerId",
                type: "uuid",
                notNull: true,
                hasDefault: false,
                references: { table: "auth.users", column: "id" },
              },
            ],
          }),
          table({ schema: "storage", name: "objects", rlsEnabled: true }),
          table({ schema: "private", name: "secrets" }),
        ],
      }),
    );
    expect(m.tables.map((t) => t.table)).toEqual(["notes", "storage.objects"]);
    const notes = m.tables[0];
    expect(notes?.columns).toEqual(["id", "ownerid"]);
    expect(notes?.columnInfo?.[0]).toEqual({
      name: "id",
      type: "uuid",
      nullable: false,
      hasDefault: true,
      references: null,
    });
    expect(notes?.columnInfo?.[1]).toMatchObject({
      references: { table: "auth.users", column: "id" },
      sqlName: "ownerId",
    });
    expect(notes?.location).toEqual(SNAPSHOT_REF);
  });

  it("reads a policy exactly as the database holds it, including a missing TO clause", () => {
    const m = ok(
      snapshot({
        tables: [table()],
        policies: [
          {
            schema: "public",
            table: "notes",
            name: "anyone writes",
            command: "UPDATE",
            roles: "{public}",
            using: "true",
            withCheck: null,
          },
          {
            schema: "public",
            table: "notes",
            name: "owner reads",
            command: "SELECT",
            roles: ["authenticated"],
            using: "(owner_id = auth.uid())",
            withCheck: "",
          },
          { schema: "public", table: "notes", name: "everything", command: "ALL", roles: [] },
          { schema: "public", table: "ghost", name: "orphan", command: "SELECT", roles: [] },
        ],
      }),
    );
    const notes = m.tables[0];
    expect(notes?.policies).toEqual(["anyone writes", "owner reads", "everything"]);
    expect(notes?.policyDetails[0]).toMatchObject({
      command: "update",
      roles: ["public"],
      using: "true",
      check: null,
    });
    expect(notes?.policyDetails[1]).toMatchObject({
      command: "select",
      roles: ["authenticated"],
      using: "(owner_id = auth.uid())",
      check: null,
    });
    // No TO clause means PUBLIC, which is how Postgres reports it and how the rules must read it.
    expect(notes?.policyDetails[2]).toMatchObject({ command: "all", roles: ["public"] });
    expect(m.notes).toContain("1 policies on relations outside the snapshot");
  });

  it("takes the execute grants as facts instead of assuming Supabase defaults", () => {
    const m = ok(
      snapshot({
        functions: [
          {
            schema: "public",
            name: "cleanup_expired",
            securityDefiner: true,
            returns: "void",
            arguments: "",
            body: "delete from messages where expires_at < now()",
            executeGrants: ["service_role"],
          },
          {
            schema: "public",
            name: "leaky",
            securityDefiner: true,
            returns: "SETOF invoices",
            arguments: "p_invoice_id uuid, p_limit integer DEFAULT 20",
            body: "select * from public.invoices where id = p_invoice_id",
            executeGrants: ["PUBLIC"],
          },
        ],
      }),
    );
    // The revoked function is the false positive a migration reader cannot rule out; the database can.
    expect(m.sqlFunctions[0]).toMatchObject({
      name: "cleanup_expired",
      grantedTo: ["service_role"],
      checksCaller: false,
    });
    // PUBLIC holds EXECUTE, so anon and authenticated do too.
    expect(m.sqlFunctions[1]).toMatchObject({
      name: "leaky",
      grantedTo: ["anon", "authenticated", "public"],
      returns: "setof invoices",
      args: "uuid, integer",
      tables: ["invoices"],
    });
    expect(m.sqlFunctions[1]?.params).toEqual([
      { name: "p_invoice_id", type: "uuid" },
      { name: "p_limit", type: "integer", default: true },
    ]);
  });

  it("reads text parameters a definer body glues into EXECUTE", () => {
    const m = ok(
      snapshot({
        functions: [
          {
            schema: "public",
            name: "search_orders",
            securityDefiner: true,
            returns: "SETOF orders",
            arguments: "p_status text, p_limit integer DEFAULT 20",
            body: "begin return query execute 'select * from orders where status = ''' || p_status || ''' limit ' || p_limit; end",
            executeGrants: ["PUBLIC"],
          },
          {
            schema: "public",
            name: "search_orders_safe",
            securityDefiner: true,
            returns: "SETOF orders",
            arguments: "p_status text",
            body: "begin return query execute 'select * from orders where status = $1' using p_status; end",
            executeGrants: ["PUBLIC"],
          },
        ],
      }),
    );
    // The integer is glued in too, but it cannot close a quote.
    expect(m.sqlFunctions[0]?.sqlFromParams).toEqual(["p_status"]);
    expect(m.sqlFunctions[1]?.sqlFromParams).toBeUndefined();
  });

  it("sees the caller's identity in a body, in a default, and through a call", () => {
    const m = ok(
      snapshot({
        functions: [
          {
            schema: "public",
            name: "current_tenant",
            securityDefiner: true,
            arguments: "",
            body: "select tenant_id from members where user_id = auth.uid()",
            executeGrants: ["authenticated"],
          },
          {
            schema: "public",
            name: "by_default",
            securityDefiner: true,
            arguments: "p_user uuid DEFAULT auth.uid()",
            body: "select 1",
            executeGrants: ["authenticated"],
          },
          {
            schema: "public",
            name: "through_a_call",
            securityDefiner: true,
            arguments: "",
            body: "select * from invoices where tenant_id = current_tenant()",
            executeGrants: ["authenticated"],
          },
          {
            schema: "public",
            name: "role_only",
            securityDefiner: true,
            arguments: "p_id uuid",
            body: "select * from invoices where id = p_id and auth.role() = 'authenticated'",
            executeGrants: ["authenticated"],
          },
        ],
      }),
    );
    const checks = Object.fromEntries(m.sqlFunctions.map((f) => [f.name, f.checksCaller]));
    expect(checks).toEqual({
      current_tenant: true,
      by_default: true,
      through_a_call: true,
      // auth.role() is the same for every signed-in user, so it identifies nobody.
      role_only: false,
    });
  });

  it("takes the caller check from readsCaller when the query sent no body", () => {
    // Bodies travel only for SECURITY DEFINER functions; an invoker helper arrives as one boolean.
    const m = ok(
      snapshot({
        functions: [
          {
            schema: "public",
            name: "current_org",
            securityDefiner: false,
            arguments: "",
            body: null,
            readsCaller: true,
            executeGrants: ["authenticated"],
          },
          {
            schema: "public",
            name: "orders_of_my_org",
            securityDefiner: true,
            arguments: "",
            body: "select * from orders where org_id = current_org()",
            executeGrants: ["authenticated"],
          },
          {
            schema: "public",
            name: "plain_helper",
            securityDefiner: false,
            arguments: "",
            body: null,
            readsCaller: false,
            executeGrants: ["authenticated"],
          },
        ],
      }),
    );
    const checks = Object.fromEntries(m.sqlFunctions.map((f) => [f.name, f.checksCaller]));
    expect(checks).toEqual({ current_org: true, orders_of_my_org: true, plain_helper: false });
  });

  it("reads storage buckets and what the database says about itself", () => {
    const m = ok(
      snapshot({
        buckets: [
          { id: "avatars", public: true },
          { id: "invoices", public: false },
          { id: "", public: true },
        ],
      }),
    );
    expect(m.storageBuckets).toEqual([
      { id: "avatars", public: true, location: SNAPSHOT_REF },
      { id: "invoices", public: false, location: SNAPSHOT_REF },
    ]);
    expect(m.takenAt).toBe("2026-09-20T09:00:00Z");
    expect(m.postgres).toBe("17.11");
  });

  it("reads whether the Data API refuses an update or delete without a filter", () => {
    const refuses = (apiSettings?: unknown) =>
      ok(snapshot(apiSettings === undefined ? {} : { apiSettings })).dataApiRefusesUnfilteredWrites;
    // A snapshot taken before the query read these settings says nothing: the rules assume Supabase.
    expect(refuses()).toBeUndefined();
    expect(refuses("not a list")).toBeUndefined();
    // What authenticator holds on every Supabase project (measured on supabase/postgres 17.6.1.167).
    expect(refuses(["session_preload_libraries=supautils, safeupdate"])).toBe(true);
    expect(refuses(['session_preload_libraries="$libdir/safeupdate.so"'])).toBe(true);
    // The owner switched it off; the most specific setting comes first and wins.
    expect(
      refuses(["safeupdate.enabled=off", "session_preload_libraries=supautils, safeupdate"]),
    ).toBe(false);
    expect(refuses(["safeupdate.enabled=0", "session_preload_libraries=safeupdate"])).toBe(false);
    expect(
      refuses([
        "safeupdate.enabled=on",
        "safeupdate.enabled=off",
        "session_preload_libraries=safeupdate",
      ]),
    ).toBe(true);
    // A PostgREST pre-request function can switch it off for each request; the server's own value
    // (ALTER SYSTEM) comes last, after every role and database setting.
    expect(
      refuses([
        "pgrst.db_pre_request=public.before_request",
        "session_preload_libraries=supautils, safeupdate",
      ]),
    ).toBe(false);
    expect(
      refuses(["pgrst.db_pre_request=", "session_preload_libraries=supautils, safeupdate"]),
    ).toBe(true);
    expect(
      refuses(["session_preload_libraries=supautils, safeupdate", "safeupdate.enabled=off"]),
    ).toBe(false);
    expect(
      refuses(["session_preload_libraries=supautils, safeupdate", "safeupdate.enabled="]),
    ).toBe(true);
    // Not preloaded at all, or no setting the snapshot can see.
    expect(refuses(["session_preload_libraries=supautils"])).toBe(false);
    expect(refuses([])).toBe(false);
    expect(refuses([42, null, "session_preload_libraries=safeupdate"])).toBe(true);
  });

  it("reads the tables a function that is not SECURITY DEFINER changes, as the database reports them", () => {
    const fn = (name: string, changes: unknown) => ({
      schema: "public",
      name,
      securityDefiner: false,
      returns: "void",
      arguments: "",
      identity: "",
      body: null,
      readsCaller: false,
      executeGrants: ["PUBLIC"],
      changes,
    });
    const m = ok(
      snapshot({
        functions: [
          fn("wipe", ["public.notes", '"Orders"', "set", "private.audit", "*"]),
          fn("reader", []),
          fn("old_snapshot", undefined),
        ],
      }),
    );
    const byName = Object.fromEntries(m.sqlFunctions.map((f) => [f.name, f.changes]));
    expect(byName).toEqual({
      wipe: ["notes", "orders", "private.audit", "*"],
      reader: undefined,
      old_snapshot: undefined,
    });
  });
});

describe("views in a live snapshot", () => {
  it("keeps security_invoker and the sources of a view, and never for a table", () => {
    const text = snapshot({
      tables: [
        table({ name: "invoices", securityInvoker: true, sources: ["nothing"] }),
        {
          schema: "public",
          name: "invoice_totals",
          rlsEnabled: false,
          kind: "view",
          columns: [],
          grants: SUPABASE_GRANTS,
          securityInvoker: false,
          sources: ["Invoices", "auth.users"],
        },
        {
          schema: "public",
          name: "daily",
          rlsEnabled: false,
          kind: "matview",
          columns: [],
          grants: SUPABASE_GRANTS,
          securityInvoker: true,
          sources: ["invoices"],
        },
        {
          schema: "public",
          name: "old_view",
          rlsEnabled: false,
          kind: "view",
          columns: [],
          grants: SUPABASE_GRANTS,
        },
      ],
    });
    const r = parseLiveSnapshot(text);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const by = new Map(r.model.tables.map((t) => [t.table, t]));
    expect(by.get("invoices")?.viewSecurityInvoker).toBeUndefined();
    expect(by.get("invoices")?.viewSources).toBeUndefined();
    expect(by.get("invoice_totals")).toMatchObject({
      kind: "view",
      viewSecurityInvoker: false,
      viewSources: ["invoices", "auth.users"],
    });
    // A materialized view is a stored copy whatever the option says.
    expect(by.get("daily")?.viewSecurityInvoker).toBe(false);
    // A snapshot taken before the query read views says nothing about them.
    expect(by.get("old_view")?.viewSecurityInvoker).toBeUndefined();
    expect(by.get("old_view")?.viewSources).toBeUndefined();
  });
});
