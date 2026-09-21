import type { Finding } from "@auditai/core";
import { describe, expect, it } from "vitest";
import { reachesFailOn } from "./fail-on.js";

const finding = (over: Partial<Finding>): Finding => ({
  id: "AUDIT-001",
  ruleId: "supabase.table-without-rls",
  title: "t",
  status: "likely",
  severity: "high",
  confidence: 0.9,
  entrypoints: [],
  sources: [],
  sinks: [],
  path: [],
  evidence: [],
  createdAt: "2026-09-21T00:00:00Z",
  updatedAt: "2026-09-21T00:00:00Z",
  ...over,
});

describe("reachesFailOn", () => {
  it("fails the build on a headline that reached the status", () => {
    expect(reachesFailOn([finding({ tier: "headline" })], "likely")).toBe(true);
    expect(reachesFailOn([finding({})], "likely")).toBe(true);
    expect(reachesFailOn([finding({ tier: "headline" })], "confirmed")).toBe(false);
  });

  it("never fails the build on a lead, whatever the gate", () => {
    const lead = finding({ tier: "lead", severity: "medium", ruleSeverity: "critical" });
    expect(reachesFailOn([lead], "candidate")).toBe(false);
    expect(reachesFailOn([lead], "likely")).toBe(false);
  });

  it("never fails the build on a suppressed finding", () => {
    expect(reachesFailOn([finding({ status: "suppressed" })], "candidate")).toBe(false);
  });
});
