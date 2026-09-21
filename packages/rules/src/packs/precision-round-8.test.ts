import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Finding } from "@auditai/core";
import { buildGraph } from "@auditai/graph";
import { parseProject } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { runRules } from "../rule.js";
import { supabaseAuthorizationPack } from "./supabase-authorization.js";
import { supabaseSqlPoliciesPack } from "./supabase-sql-policies.js";
import { supabaseStorageRpcPack } from "./supabase-storage-rpc.js";

/**
 * Precision round 8 (20 September 2026): causes the fourth blind sample and the live-schema work
 * showed (docs/realworld/2026-09-20-schema-truth.md). Each accepted shape sits next to the shape that
 * must stay a finding.
 */

const ANON = `import { createClient } from "@supabase/supabase-js";
export function anon() { return createClient(process.env.SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!); }
`;
const ROUTE = `import { anon } from "@/lib/anon";
export async function GET(req: Request) {
  const { data } = await anon().from("notes").select("*");
  const path = new URL(req.url).searchParams.get("path") ?? "";
  await anon().storage.from("invoices").remove([path]);
  return Response.json(data);
}
export async function PATCH(req: Request) {
  const body = await req.json();
  await anon().from("notes").update(body).eq("id", body.id);
  return Response.json({ ok: true });
}`;
const TABLE = `create table public.notes (id uuid primary key, owner_id uuid not null, email text, body text);
alter table public.notes enable row level security;`;

function scan(sql: string): Finding[] {
  const dir = mkdtempSync(join(tmpdir(), "auditai-rules-round8-"));
  const files: Record<string, string> = {
    "lib/anon.ts": ANON,
    "app/api/notes/route.ts": ROUTE,
    "supabase/migrations/0001.sql": `${TABLE}\n${sql}`,
  };
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  const model = parseProject(dir, { sqlDirs: ["supabase/migrations"] });
  return runRules(
    [...supabaseAuthorizationPack, ...supabaseSqlPoliciesPack, ...supabaseStorageRpcPack],
    model,
    buildGraph(model),
    {
      now: "2026-09-20T00:00:00Z",
    },
  );
}

/** The two policy rules under test; the fixture's PATCH route also trips mass assignment, which is not the subject here. */
const POLICY_RULES = new Set([
  "anon-write-policy",
  "rls-policy-without-caller-predicate",
  "storage-policy-without-owner-check",
]);
const rules = (f: Finding[]): string[] =>
  f
    .filter((x) => x.status !== "suppressed")
    .map((x) => x.ruleId.replace("supabase.", ""))
    .filter((id) => POLICY_RULES.has(id))
    .sort();

describe("precision round 8", () => {
  it("counts auth.email() as the caller, because it names one person out of the JWT", () => {
    // Weaker than auth.uid() — an address can be reassigned — but it is the caller's identity, and a
    // policy built on it is not the same defect as `using (true)`.
    expect(
      rules(
        scan(`create policy "own notes" on public.notes for select using (email = auth.email());`),
      ),
    ).toEqual([]);
    // auth.role() is the same string for every signed-in user, so it identifies nobody.
    expect(
      rules(
        scan(
          `create policy "any signed in" on public.notes for select using (auth.role() = 'authenticated');`,
        ),
      ),
    ).toEqual(["rls-policy-without-caller-predicate"]);
  });

  it("reports an open write policy once, not once per rule", () => {
    // anon-write-policy states it precisely and deterministically; the caller-predicate rule would
    // otherwise say the same thing about the same policy.
    expect(
      rules(scan(`create policy "anyone writes" on public.notes for update using (true);`)),
    ).toEqual(["anon-write-policy"]);
  });

  it("keeps both findings for a for-all policy, because that one opens reads as well", () => {
    expect(
      rules(scan(`create policy "anyone everything" on public.notes for all using (true);`)),
    ).toEqual(["anon-write-policy", "rls-policy-without-caller-predicate"]);
  });

  it("still reports a read policy that ties rows to nobody", () => {
    expect(
      rules(scan(`create policy "everyone reads" on public.notes for select using (true);`)),
    ).toEqual(["rls-policy-without-caller-predicate"]);
  });

  it("ignores a storage policy only the service role can satisfy, however it is written", () => {
    // service_role is never a user session and bypasses RLS anyway, so such a policy decides nothing.
    const bucket = `insert into storage.buckets (id, name, public) values ('invoices', 'invoices', false);`;
    const viaTo = `${bucket}
create policy "service deletes" on storage.objects for delete to service_role using (bucket_id = 'invoices');`;
    const viaPredicate = `${bucket}
create policy "service updates" on storage.objects for update using (bucket_id = 'invoices' and auth.role() = 'service_role');`;
    expect(rules(scan(viaTo))).toEqual([]);
    expect(rules(scan(viaPredicate))).toEqual([]);
    // The same policy open to everyone stays a finding.
    const open = `${bucket}
create policy "anyone deletes" on storage.objects for delete using (bucket_id = 'invoices');`;
    expect(rules(scan(open))).toEqual(["storage-policy-without-owner-check"]);
  });
});
