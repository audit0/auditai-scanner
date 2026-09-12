import type { ProjectModel, SqlFunctionInfo } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import {
  callerCheckingFunctions,
  callsFunctionIn,
  sqlFunctionsOf,
  storageBucketsOf,
} from "./sql-functions.js";

const model = (extra: Partial<ProjectModel> = {}): ProjectModel => ({
  root: "/x",
  files: [],
  routes: [],
  clientFactories: [],
  authHelpers: [],
  tables: [],
  exposures: [],
  fileIgnores: {},
  warnings: [],
  ...extra,
});

const fn = (name: string, checksCaller: boolean): SqlFunctionInfo => ({
  name,
  securityDefiner: true,
  checksCaller,
  grantedTo: ["anon", "authenticated"],
  location: { file: "m.sql", line: 1 },
});

describe("SQL views over the model", () => {
  it("treats a model without parsed SQL as knowing no functions and no buckets", () => {
    expect(sqlFunctionsOf(model())).toEqual([]);
    expect(storageBucketsOf(model())).toEqual([]);
    expect(callerCheckingFunctions(model()).size).toBe(0);
  });

  it("lists the functions whose body reads the caller", () => {
    const m = model({
      sqlFunctions: [fn("is_member", true), fn("leaky", false), fn("private.has_access", true)],
    });
    expect([...callerCheckingFunctions(m)]).toEqual(["is_member", "private.has_access"]);
  });

  it("finds calls to known functions inside policy expressions", () => {
    const names = new Set(["is_account_member", "private.has_access"]);
    expect(callsFunctionIn("public.is_account_member(account_id, 'admin')", names)).toBe(true);
    expect(callsFunctionIn('"private"."has_access"(id)', names)).toBe(true);
    expect(callsFunctionIn("id in (select is_account_member(x))", names)).toBe(true);
    expect(callsFunctionIn("status = 'is_account_member(x)'", names)).toBe(false);
    expect(callsFunctionIn("public.has_access(id)", names)).toBe(false);
    expect(callsFunctionIn("is_account_member(account_id)", new Set())).toBe(false);
  });
});
