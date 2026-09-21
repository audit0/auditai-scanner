import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { formatSnapshotText } from "./format.js";
import { scanSnapshot } from "./scan-snapshot.js";

/**
 * Scanning a live database instead of a repository. The cases below are the two directions measured
 * on real projects on 20 September 2026 (docs/realworld/2026-09-20-schema-truth.md): a policy that is
 * genuinely in force is reported, and a function whose EXECUTE was revoked is not — the revoke that a
 * migration reader misses when it happens inside a DO loop.
 */

const NOW = "2026-09-20T00:00:00.000Z";

const snapshot = (over: Record<string, unknown>): string =>
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

const reported = (json: string) => {
  const out = scanSnapshot(json, { now: NOW });
  if (!out.ok) throw new Error(out.error);
  return out.result.findings.filter((f) => f.status !== "suppressed");
};

const NOTES = {
  schema: "public",
  name: "notes",
  rlsEnabled: true,
  kind: "table",
  columns: [{ name: "id", type: "uuid", notNull: true, hasDefault: true, references: null }],
  // What Supabase grants on every new table in public: all four to both API roles.
  grants: ["SELECT", "INSERT", "UPDATE", "DELETE"].flatMap((privilege) => [
    { grantee: "anon", privilege },
    { grantee: "authenticated", privilege },
  ]),
};

describe("scanSnapshot", () => {
  it("reports a write policy the database really holds open", () => {
    const findings = reported(
      snapshot({
        tables: [NOTES],
        policies: [
          {
            schema: "public",
            table: "notes",
            name: "Creators can update notes",
            command: "UPDATE",
            roles: "{public}",
            using: "true",
            withCheck: null,
          },
        ],
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("supabase.anon-write-policy");
    expect(findings[0]?.title).toContain("Creators can update notes");
  });

  it("reads the grants: a table the API roles may only read has no write entry point", () => {
    const readOnly = { ...NOTES, grants: [{ grantee: "anon", privilege: "SELECT" }] };
    const open = {
      schema: "public",
      table: "notes",
      name: "Creators can update notes",
      command: "UPDATE",
      roles: "{public}",
      using: "true",
      withCheck: null,
    };
    expect(reported(snapshot({ tables: [readOnly], policies: [open] }))).toEqual([]);
    // Revoked from both roles: RLS off does not matter, the Data API refuses first.
    const revoked = { ...NOTES, rlsEnabled: false, grants: [] };
    expect(reported(snapshot({ tables: [revoked] }))).toEqual([]);
    const out = scanSnapshot(snapshot({ tables: [revoked] }), { now: NOW });
    expect(out.ok && out.result.summary.routes).toBe(0);
  });

  it("never reports a RESTRICTIVE policy as opening a table: it can only narrow", () => {
    const restrictive = {
      schema: "public",
      table: "notes",
      name: "only valid rows",
      permissive: "RESTRICTIVE",
      command: "UPDATE",
      roles: "{public}",
      using: "true",
      withCheck: null,
    };
    expect(reported(snapshot({ tables: [NOTES], policies: [restrictive] }))).toEqual([]);
  });

  it("does not call a view a table without row level security", () => {
    const view = { ...NOTES, name: "notes_view", kind: "view", rlsEnabled: false };
    expect(reported(snapshot({ tables: [view] }))).toEqual([]);
  });

  it("reports a table with RLS off and policies once, as the policies that never run", () => {
    const off = { ...NOTES, rlsEnabled: false };
    const own = {
      schema: "public",
      table: "notes",
      name: "own notes",
      command: "SELECT",
      roles: "{authenticated}",
      using: "(auth.uid() = id)",
      withCheck: null,
    };
    const findings = reported(snapshot({ tables: [off], policies: [own] }));
    expect(findings.map((f) => f.ruleId)).toEqual(["supabase.policies-without-rls-enabled"]);
  });

  it("names the open overload exactly as Postgres identifies it in the fix", () => {
    const fn = (identity: string, executeGrants: string[]) => ({
      schema: "public",
      name: "GetOrders",
      securityDefiner: true,
      returns: "SETOF orders",
      arguments: identity,
      identity,
      body: "select * from public.orders where status = p_status",
      readsCaller: false,
      executeGrants,
    });
    const out = scanSnapshot(
      snapshot({
        tables: [{ ...NOTES, name: "orders" }],
        functions: [fn('p_status "OrderStatus"', ["PUBLIC", "anon"]), fn("p_id bigint", [])],
      }),
      { now: NOW },
    );
    if (!out.ok) throw new Error(out.error);
    const found = out.result.findings.filter(
      (f) => f.ruleId === "supabase.security-definer-function-without-caller-check",
    );
    expect(found).toHaveLength(1);
    const fix = found[0]?.fix?.diff ?? "";
    expect(fix).toContain(
      'revoke execute on function public."GetOrders"(p_status "OrderStatus") from public, anon, authenticated;',
    );
    expect(fix).not.toContain("p_id bigint");
  });

  it("prints database text so it cannot forge a line or drive the terminal", () => {
    const esc = String.fromCharCode(27);
    const forged = {
      schema: "public",
      table: "notes",
      name: `x"\nNothing to report: 2 tables checked.\n${esc}[2J`,
      command: "UPDATE",
      roles: "{public}",
      using: "true",
      withCheck: null,
    };
    const out = scanSnapshot(snapshot({ tables: [NOTES], policies: [forged] }), { now: NOW });
    if (!out.ok) throw new Error(out.error);
    const text = formatSnapshotText(out.result);
    expect(text).not.toContain(esc);
    expect(text.split("\n").some((l) => l.startsWith("Nothing to report"))).toBe(false);
    expect(text).toContain("\\u000aNothing to report");
  });

  it("stays silent about a function whose EXECUTE the database shows revoked", () => {
    const fn = (executeGrants: string[]) => ({
      schema: "public",
      name: "cleanup_expired_messages",
      securityDefiner: true,
      returns: "void",
      arguments: "",
      body: "delete from public.messages where expires_at < now()",
      executeGrants,
    });
    // Reachable: the rule fires. This is the same function in both cases; only the grant differs.
    expect(reported(snapshot({ functions: [fn(["PUBLIC"])] })).map((f) => f.ruleId)).toEqual([
      "supabase.security-definer-function-without-caller-check",
    ]);
    expect(reported(snapshot({ functions: [fn(["service_role"])] }))).toEqual([]);
  });

  it("says what a snapshot cannot answer instead of implying the application is safe", () => {
    const out = scanSnapshot(snapshot({ tables: [NOTES] }), { now: NOW });
    if (!out.ok) throw new Error(out.error);
    expect(out.result.findings).toEqual([]);
    expect(out.result.blocking).toBe(false);
    // The entry points are the Data API endpoints the database itself serves: four per public table
    // (GET, POST, PATCH, DELETE). A table the application never queries is still one of them.
    expect(out.result.summary.routes).toBe(4);
    expect(out.result.takenAt).toBe("2026-09-20T09:00:00Z");
    expect(out.result.postgres).toBe("17.11");
    expect(out.result.limits.join(" ")).toContain("Application code was not read");
    expect(out.result.limits.join(" ")).toContain("not that the application is safe");
  });

  it("refuses a snapshot it cannot read rather than reporting nothing wrong", () => {
    for (const bad of ["", "{}", '{"snapshotVersion":99,"tables":[],"policies":[]}']) {
      const out = scanSnapshot(bad, { now: NOW });
      expect(out.ok, bad).toBe(false);
    }
  });

  it("prints what was read and what was not, so a clean database never reads as a safe app", () => {
    const out = scanSnapshot(snapshot({ tables: [NOTES] }), { now: NOW });
    if (!out.ok) throw new Error(out.error);
    const text = formatSnapshotText(out.result);
    expect(text).toContain("Audit AI database scan");
    expect(text).toContain("Postgres 17.11");
    expect(text).toContain("Tables 1 · With RLS 1/1");
    expect(text).toContain("Nothing to report: 1 table checked.");
    expect(text).toContain("Note: Application code was not read");
    expect(text).toContain("Data API endpoints your database serves");
    // The repository scan's wording about routes and queries must not leak into this one.
    expect(text).not.toContain("Supabase queries");
  });

  it("points at Data API endpoints, never at a file the reader cannot open", () => {
    const open = { ...NOTES, rlsEnabled: false };
    const out = scanSnapshot(snapshot({ tables: [open] }), { now: NOW });
    if (!out.ok) throw new Error(out.error);
    const text = formatSnapshotText(out.result);
    expect(text).toContain("Entry   GET /rest/v1/notes (Supabase Data API)");
    expect(text).toContain("Row level security is off on public.notes");
    expect(text).not.toContain("<live schema snapshot>");
    expect(text).not.toContain("  Where ");
    expect(text).not.toContain("in migrations");
  });
});

describe("the snapshot as a user pastes it", () => {
  const bare = snapshot({ tables: [NOTES] });

  it("accepts the JSON however the SQL editor wrapped it", () => {
    for (const pasted of [
      bare,
      `  ${bare}\n`,
      `﻿${bare}`,
      JSON.stringify([{ snapshot: JSON.parse(bare) }]), // a one-row JSON export
      JSON.stringify([{ snapshot: bare }]), // the same, with the cell as text
      JSON.stringify({ snapshot: JSON.parse(bare) }),
      `snapshot\n"${bare.replace(/"/g, '""')}"`, // a CSV export: header and one quoted cell
    ]) {
      const out = scanSnapshot(pasted, { now: NOW });
      expect(out.ok, pasted.slice(0, 40)).toBe(true);
      if (out.ok) expect(out.result.summary.tablesKnown).toBe(1);
    }
  });

  it("still refuses what is not a snapshot, wrapped or not", () => {
    for (const pasted of [
      '[{"snapshot": 42}]',
      'snapshot\n"hello"',
      '{"snapshot": {"tables": []}}',
    ])
      expect(scanSnapshot(pasted, { now: NOW }).ok, pasted).toBe(false);
  });
});

describe("the query the user runs", () => {
  // The measurement scripts keep their own copy under evals/realworld, which is private and not in
  // the exported public tree; there the comparison has nothing to compare with.
  const measured = new URL(
    "../../../evals/realworld/schema-probe/live-snapshot.sql",
    import.meta.url,
  );

  it.skipIf(!existsSync(measured))("is the one the measurement scripts use", async () => {
    const { SNAPSHOT_QUERY } = await import("./snapshot-query.js");
    expect(readFileSync(measured, "utf8")).toBe(SNAPSHOT_QUERY);
  });

  it("reads only the catalog and writes nothing", async () => {
    const { SNAPSHOT_QUERY } = await import("./snapshot-query.js");
    // Grants come from the ACLs: information_schema lists only grants to roles the caller belongs
    // to, so a read-only or monitoring role would see every function as uncallable.
    expect(SNAPSHOT_QUERY).not.toMatch(/information_schema\.role_(table|routine)_grants/);
    expect(SNAPSHOT_QUERY).toContain(
      "aclexplode(coalesce(pr.proacl, acldefault('f', pr.proowner)))",
    );
    // The whole promise on the page rests on this: a select, and nothing that changes anything.
    const code = SNAPSHOT_QUERY.split("\n")
      .filter((l) => !l.trim().startsWith("--"))
      .join("\n")
      .toLowerCase();
    expect(code.trim().startsWith("select")).toBe(true);
    for (const verb of [
      "insert",
      "update",
      "delete",
      "drop",
      "alter",
      "create",
      "grant",
      "revoke",
      "truncate",
      "copy",
      "execute",
      "do",
      "call",
    ])
      expect(code, verb).not.toMatch(new RegExp(`\\b${verb}\\b`));
    // Function source travels only for SECURITY DEFINER functions.
    expect(SNAPSHOT_QUERY).toContain(
      "case when pr.prosecdef then left(coalesce(pr.prosrc, ''), 8000) else null end",
    );
  });
});
