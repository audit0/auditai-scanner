import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isBlocking } from "@auditai/core";
import { buildGraph } from "@auditai/graph";
import { parseProject } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { defaultRules, runRules } from "./index.js";

describe("suppressions", () => {
  it("turns ignored findings into suppressed ones with the reason attached", () => {
    const dir = mkdtempSync(join(tmpdir(), "auditai-supp-"));
    mkdirSync(join(dir, "app/api/public"), { recursive: true });
    writeFileSync(
      join(dir, "app/api/public/route.ts"),
      `import { createClient } from "@supabase/supabase-js";
// auditai:ignore supabase.service-role-query-without-authentication -- public waitlist
export async function POST(req: Request) {
  const admin = createClient(process.env.URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
  await admin.from("waitlist").insert({ email: "x" });
  return new Response("ok");
}
`,
    );
    const model = parseProject(dir);
    const findings = runRules(defaultRules, model, buildGraph(model), {
      now: "2026-09-11T00:00:00Z",
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.status).toBe("suppressed");
    expect(findings[0]?.evidence.at(-1)?.summary).toContain("public waitlist");
    expect(isBlocking(findings[0] as never)).toBe(false);
  });
});
