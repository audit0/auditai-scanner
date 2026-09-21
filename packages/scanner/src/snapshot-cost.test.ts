import { SNAPSHOT_LIMITS } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { scanSnapshot } from "./scan-snapshot.js";

/**
 * What a snapshot can cost. /api/check runs this on anything anyone pastes, so the time must grow with
 * the size of the input, not with its square. Each case below took 20 s to 100 s before the graph was
 * indexed and the patterns were anchored (review of 21 September 2026); the bound leaves a wide margin
 * for a slow CI machine and still fails on any quadratic path at these sizes.
 */

const snapshot = (over: Record<string, unknown>): string =>
  JSON.stringify({
    snapshotVersion: 1,
    tables: [],
    policies: [],
    functions: [],
    buckets: [],
    ...over,
  });

const timed = (json: string): number => {
  const t = performance.now();
  scanSnapshot(json);
  return performance.now() - t;
};

const BOUND_MS = 5_000;

describe("the cost of a snapshot", () => {
  it("stays linear in the number of tables", () => {
    const tables = Array.from({ length: 3_000 }, (_, i) => ({ schema: "public", name: `t${i}` }));
    expect(timed(snapshot({ tables }))).toBeLessThan(BOUND_MS);
  });

  it("stays linear in the number of functions that call each other", () => {
    const functions = [
      ...Array.from({ length: 3_000 }, (_, i) => ({ name: `c${i}`, readsCaller: true })),
      ...Array.from({ length: 7_000 }, (_, i) => ({
        name: `n${i}`,
        securityDefiner: true,
        executeGrants: ["anon"],
        body: `select c${i % 3_000}(1)`,
      })),
    ];
    expect(timed(snapshot({ functions }))).toBeLessThan(BOUND_MS);
  });

  it("reads the longest policy and argument list it accepts without backtracking", () => {
    const n = SNAPSHOT_LIMITS.text;
    const table = {
      schema: "public",
      name: "t",
      rlsEnabled: true,
      columns: [{ name: "owner_id" }],
    };
    const objects = { schema: "storage", name: "objects", rlsEnabled: true };
    const json = snapshot({
      tables: [table, objects],
      policies: [
        {
          schema: "public",
          table: "t",
          name: "p",
          command: "ALL",
          roles: ["anon"],
          using: "a".repeat(n),
        },
        {
          schema: "storage",
          table: "objects",
          name: "b",
          command: "SELECT",
          roles: ["authenticated"],
          using: "bucket_id in (".repeat(Math.floor(n / 14)),
        },
      ],
      functions: [
        { name: "f", body: "select auth.uid()" },
        { name: "g", arguments: `a${" ".repeat(n - 2)}b` },
      ],
    });
    expect(timed(json)).toBeLessThan(BOUND_MS);
  });

  it("refuses more than one snapshot may hold, as a whole, instead of reading part of it", () => {
    const tables = Array.from({ length: SNAPSHOT_LIMITS.tables + 1 }, (_, i) => ({
      schema: "public",
      name: `t${i}`,
    }));
    const out = scanSnapshot(snapshot({ tables }));
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error).toMatch(/^too large: 5001 tables/);
    const long = scanSnapshot(
      snapshot({
        tables: [{ schema: "public", name: "t" }],
        policies: [
          { schema: "public", table: "t", name: "p", using: "x".repeat(SNAPSHOT_LIMITS.text + 1) },
        ],
      }),
    );
    expect(long.ok).toBe(false);
  });
});
