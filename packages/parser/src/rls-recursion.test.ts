import { describe, expect, it } from "vitest";
import type { PolicyDetail, RlsTable } from "./model.js";
import { recursivePolicies } from "./rls-recursion.js";

const policy = (over: Partial<PolicyDetail>): PolicyDetail => ({
  name: "p",
  command: "select",
  roles: [],
  using: null,
  check: null,
  location: { file: "m.sql", line: 1 },
  ...over,
});
const table = (policyDetails: PolicyDetail[], extra: Partial<RlsTable> = {}): RlsTable => ({
  table: "profiles",
  rlsEnabled: true,
  policies: policyDetails.map((p) => p.name),
  policyDetails,
  columns: ["id", "role"],
  location: { file: "m.sql", line: 1 },
  ...extra,
});
const selfRead = "exists (select 1 from public.profiles where id = auth.uid() and role = 'admin')";

describe("recursivePolicies", () => {
  it("names a SELECT or ALL policy that reads its own table", () => {
    expect(recursivePolicies(table([policy({ name: "admins", using: selfRead })]))).toEqual([
      "admins",
    ]);
    expect(
      recursivePolicies(
        table([
          policy({ name: "all", command: "all", using: "id in (select id from profiles p)" }),
        ]),
      ),
    ).toEqual(["all"]);
  });

  it("ignores other commands, helper functions, other tables, other roles and unread policies", () => {
    expect(recursivePolicies(table([policy({ command: "update", using: selfRead })]))).toEqual([]);
    expect(recursivePolicies(table([policy({ using: "public.is_admin()" })]))).toEqual([]);
    expect(
      recursivePolicies(table([policy({ using: "exists (select 1 from profiles_extra x)" })])),
    ).toEqual([]);
    expect(
      recursivePolicies(table([policy({ roles: ["service_role"], using: selfRead })])),
    ).toEqual([]);
    expect(recursivePolicies(table([policy({ permissive: false, using: selfRead })]))).toEqual([]);
    expect(
      recursivePolicies(table([policy({ using: selfRead })], { policiesUnread: true })),
    ).toEqual([]);
  });
});
