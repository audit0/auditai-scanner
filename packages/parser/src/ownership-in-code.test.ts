import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import type { QueryFilter } from "./model.js";
import { parseProject } from "./parse-project.js";

function tempProject(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "auditai-ownership-in-code-"));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}

const LIB = `import { createClient } from "@supabase/supabase-js";
export function admin() { return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!); }
`;

/** The filters on `configs` of a GET handler with this body, in source order. */
function configFilters(handlerBody: string): QueryFilter[] {
  const model = parseProject(
    tempProject({
      "lib/supabase.ts": LIB,
      "app/api/return/route.ts": `import { admin } from "@/lib/supabase";
export async function GET(req: Request) {
  const token = new URL(req.url).searchParams.get("token");
${handlerBody}
  return new Response(null);
}
`,
    }),
  );
  return model.routes.flatMap((r) =>
    r.queries.filter((q) => q.table === "configs").flatMap((q) => q.filters),
  );
}

describe("rows of a query the request only switches on", () => {
  // The conditional-rows reading was cut in the final review (the request can also supply the query's
  // filter or payload, verify-W2-r5 b2, b4), so these rows are the caller's input again, as on main.
  it("taints the rows of `token ? await query : { data: null }`, as main does", () => {
    const [f] = configFilters(`  const { data: app } = token
    ? await admin().from("applications").select("organization_id").eq("token", token).maybeSingle()
    : { data: null };
  if (!app) return new Response(null, { status: 400 });
  await admin().from("configs").select("*").eq("organization_id", app.organization_id);`);
    expect(f).toMatchObject({ column: "organization_id", inputDerived: true });
  });

  it("still taints a fallback the caller sends", () => {
    const [f] = configFilters(`  const { data: app } = token
    ? await admin().from("applications").select("organization_id").eq("token", token).maybeSingle()
    : { data: { organization_id: new URL(req.url).searchParams.get("org") } };
  if (!app) return new Response(null, { status: 400 });
  await admin().from("configs").select("*").eq("organization_id", app.organization_id);`);
    expect(f).toMatchObject({ column: "organization_id", inputDerived: true });
  });

  // Round 8 review 4: `Array.from` and `Buffer.from` have a `from` segment but hand back the caller's input.
  it("taints `cond ? Array.from(body.ids) : []`, which is input and not a query's rows", () => {
    const [f] =
      configFilters(`  const orgs = token ? Array.from(new Set(new URL(req.url).searchParams.getAll("org"))) : [];
  await admin().from("configs").select("*").in("organization_id", orgs);`);
    expect(f).toMatchObject({ column: "organization_id", inputDerived: true });
  });

  it("taints `cond ? Buffer.from(token).toString() : null`", () => {
    const [f] = configFilters(`  const org = token ? Buffer.from(token, "base64").toString() : null;
  await admin().from("configs").select("*").eq("organization_id", org);`);
    expect(f).toMatchObject({ column: "organization_id", inputDerived: true });
  });
});
