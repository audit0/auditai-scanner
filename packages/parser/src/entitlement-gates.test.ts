import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseProject } from "./parse-project.js";

/** Route exits decided by an entitlement column of the caller's own row (RouteHandler.entitlementChecks). */

function routeOf(handler: string) {
  const dir = mkdtempSync(join(tmpdir(), "auditai-entitlement-"));
  const files: Record<string, string> = {
    "lib/supabase/server.ts": `import { createServerClient } from "@supabase/ssr";
export async function createClient() { return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, { cookies: {} as never }); }
`,
    "app/api/generate/route.ts": handler,
  };
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  const r = parseProject(dir).routes.find((x) => x.entry === "POST /api/generate");
  if (!r) throw new Error("no route");
  return r;
}

const HEAD = `import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
export async function POST() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
`;

describe("entitlement checks in routes", () => {
  it("records an exit decided by credits read off the caller's own profile", () => {
    const r = routeOf(`${HEAD}
  const { data: profile } = await supabase.from("profiles").select("credits").eq("id", user.id).single();
  if (!profile || profile.credits <= 0) {
    return NextResponse.json({ error: "No credits remaining." }, { status: 402 });
  }
  return NextResponse.json({ ok: true });
}
`);
    expect(r.entitlementChecks).toEqual([
      expect.objectContaining({ table: "profiles", column: "credits", source: "profile.credits" }),
    ]);
  });

  it("ignores a row picked by a request value, a non-entitlement column and a check that does not exit", () => {
    const byInput = routeOf(`import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
export async function POST(req: Request) {
  const supabase = await createClient();
  const { id } = await req.json();
  const { data: profile } = await supabase.from("profiles").select("credits").eq("id", id).single();
  if (profile.credits <= 0) return NextResponse.json({ error: "none" }, { status: 402 });
  return NextResponse.json({ ok: true });
}
`);
    expect(byInput.entitlementChecks).toBeUndefined();
    const otherColumn = routeOf(`${HEAD}
  const { data: profile } = await supabase.from("profiles").select("name").eq("id", user.id).single();
  if (!profile.name) return NextResponse.json({ error: "no name" }, { status: 400 });
  return NextResponse.json({ ok: true });
}
`);
    expect(otherColumn.entitlementChecks).toBeUndefined();
    const noExit = routeOf(`${HEAD}
  const { data: profile } = await supabase.from("profiles").select("plan").eq("id", user.id).single();
  let limit = 3;
  if (profile.plan === "pro") limit = 10;
  return NextResponse.json({ limit });
}
`);
    expect(noExit.entitlementChecks).toBeUndefined();
  });
});
