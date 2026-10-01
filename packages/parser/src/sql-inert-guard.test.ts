import { describe, expect, it } from "vitest";
import { definerGuardSkipsEveryone } from "./sql-inert-guard.js";

const body = (cond: string, lead = "") =>
  `\ndeclare v text := 'x';\nbegin\n  ${lead}if ${cond} then return new; end if;\n  if new.role is distinct from old.role then raise exception 'no'; end if;\n  return new;\nend\n`;

describe("definerGuardSkipsEveryone", () => {
  it("reads a leading test that is true for the owner as a guard that skips everyone", () => {
    for (const cond of [
      "current_user not in ('authenticated', 'anon')",
      "current_user <> 'authenticated'",
      "current_role != 'authenticated'",
      "current_user = 'postgres'",
      "current_user in ('postgres', 'service_role')",
      "(current_user not in ('authenticated')) or tg_op = 'DELETE'",
    ])
      expect(definerGuardSkipsEveryone(body(cond)), cond).toBe(true);
  });

  it("keeps a test that is false for the owner, an AND, session_user, or a guard after other statements", () => {
    for (const cond of [
      "current_user in ('authenticated', 'anon')",
      "current_user not in ('postgres', 'supabase_admin', 'authenticated')",
      "current_user = 'service_role'",
      "current_user <> 'authenticated' and auth.uid() is null",
      "session_user <> 'authenticated'",
    ])
      expect(definerGuardSkipsEveryone(body(cond)), cond).toBe(false);
    expect(
      definerGuardSkipsEveryone(body("current_user <> 'authenticated'", "perform 1;\n  ")),
    ).toBe(false);
    expect(definerGuardSkipsEveryone("")).toBe(false);
    expect(definerGuardSkipsEveryone("begin if (((( then return new;")).toBe(false);
  });
});
