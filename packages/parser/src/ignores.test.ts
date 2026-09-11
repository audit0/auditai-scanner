import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseProject } from "./parse-project.js";

function project(): string {
  const dir = mkdtempSync(join(tmpdir(), "auditai-ignores-"));
  mkdirSync(join(dir, "app/api/public"), { recursive: true });
  mkdirSync(join(dir, "app/api/other"), { recursive: true });
  writeFileSync(
    join(dir, "app/api/public/route.ts"),
    `import { createClient } from "@supabase/supabase-js";
// auditai:ignore supabase.service-role-query-without-authentication -- public endpoint by design
export async function POST(req: Request) {
  const admin = createClient(process.env.URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
  await admin.from("waitlist").insert({ email: "x" });
  return new Response("ok");
}
`,
  );
  writeFileSync(
    join(dir, "app/api/other/route.ts"),
    `/* auditai:ignore * -- legacy file, reviewed 2026-09 */
import { createClient } from "@supabase/supabase-js";
export async function GET() {
  const admin = createClient(process.env.URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
  return Response.json(await admin.from("profiles").select("*"));
}
`,
  );
  return dir;
}

describe("auditai:ignore directives", () => {
  it("attaches handler-level and file-level directives", () => {
    const m = parseProject(project());
    const post = m.routes.find((r) => r.entry === "POST /api/public");
    expect(post?.ignores).toEqual([
      expect.objectContaining({
        ruleId: "supabase.service-role-query-without-authentication",
        reason: "public endpoint by design",
      }),
    ]);
    expect(m.fileIgnores["app/api/other/route.ts"]?.[0]).toMatchObject({
      ruleId: "*",
      reason: "legacy file, reviewed 2026-09",
    });
  });
});
