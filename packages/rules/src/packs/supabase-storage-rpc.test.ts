import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildGraph } from "@auditai/graph";
import { type ProjectModel, parseProject } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { defaultRules } from "../index.js";
import { runRules } from "../rule.js";
import { policyScopesToCaller, rlsPolicyWithoutCallerPredicate } from "./supabase-authorization.js";
import {
  bucketsIn,
  securityDefinerFunctionWithoutCallerCheck,
  storageObjectAccessWithoutOwnerScope,
  storagePolicyWithoutOwnerCheck,
  supabaseStorageRpcPack,
} from "./supabase-storage-rpc.js";

const NOW = "2026-09-11T00:00:00Z";

function fixtureDir(name: string, variant: "vulnerable" | "secure"): string {
  return fileURLToPath(new URL(`../../../../evals/fixtures/${name}/${variant}/`, import.meta.url));
}

function scanDir(dir: string, sqlDirs: string[] = []) {
  const model = parseProject(dir, { sqlDirs });
  return { model, findings: runRules(defaultRules, model, buildGraph(model), { now: NOW }) };
}

function tempProject(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "auditai-storage-rpc-"));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}

const ADMIN_LIB = `import { createClient } from "@supabase/supabase-js";
export function admin() { return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!); }
export async function getUserFromRequest(req: Request) {
  const { data } = await admin().auth.getUser(req.headers.get("authorization") ?? "");
  return data.user;
}
`;

describe("storage/RPC pack on fixtures 015-018", () => {
  const cases = [
    ["015-storage-download-user-supplied-path", storageObjectAccessWithoutOwnerScope.id, true],
    ["016-storage-policy-bucket-only", storagePolicyWithoutOwnerCheck.id, false],
    [
      "017-security-definer-rpc-without-caller-check",
      securityDefinerFunctionWithoutCallerCheck.id,
      false,
    ],
    ["018-security-definer-granted-to-anon", securityDefinerFunctionWithoutCallerCheck.id, false],
  ] as const;

  it.each(cases)(
    "%s: the vulnerable app yields exactly one finding, of the expected rule",
    (name, ruleId, sharedSql) => {
      const sql = sharedSql ? ["../supabase"] : [];
      const { model, findings } = scanDir(fixtureDir(name, "vulnerable"), sql);
      expect(model.warnings).toEqual([]);
      expect(findings.map((f) => [f.ruleId, f.status])).toEqual([[ruleId, "likely"]]);
    },
  );

  it.each(cases)("%s: the secure twin yields zero findings", (name, _ruleId, sharedSql) => {
    const sql = sharedSql ? ["../supabase"] : [];
    const { model, findings } = scanDir(fixtureDir(name, "secure"), sql);
    expect(model.warnings).toEqual([]);
    expect(findings).toEqual([]);
  });

  it("rates the anon-callable function critical and the signed-in-only one high", () => {
    const high = scanDir(fixtureDir("017-security-definer-rpc-without-caller-check", "vulnerable"));
    const critical = scanDir(fixtureDir("018-security-definer-granted-to-anon", "vulnerable"));
    expect(high.findings[0]?.severity).toBe("high");
    expect(high.findings[0]?.entrypoints).toEqual([
      "GET /api/invoices/[id]",
      "POST /rest/v1/rpc/get_invoice",
    ]);
    expect(critical.findings[0]?.severity).toBe("critical");
    // Grants come from the SQL parser (model.sqlFunctions): Supabase defaults plus the GRANT statement.
    expect(critical.findings[0]?.evidence[0]?.data?.grantedTo).toEqual(
      expect.arrayContaining(["anon", "authenticated"]),
    );
  });
});

describe("supabase.storage-object-access-without-owner-scope", () => {
  it("leaves unauthenticated handlers to the unauthenticated-service-role rule (one finding)", () => {
    const dir = tempProject({
      "lib/supabase.ts": ADMIN_LIB,
      "app/api/files/route.ts": `import { admin } from "@/lib/supabase";
export async function GET(req: Request) {
  const path = new URL(req.url).searchParams.get("path")!;
  const { data } = await admin().storage.from("documents").download(path);
  return new Response(data);
}
`,
    });
    const { findings } = scanDir(dir);
    expect(findings.map((f) => f.ruleId)).toEqual([
      "supabase.service-role-query-without-authentication",
    ]);
  });

  it("stays silent for a user-scoped client (storage policies decide) and for session-scoped paths", () => {
    const dir = tempProject({
      "lib/supabase.ts": `${ADMIN_LIB}
export function asUser(token: string) { return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!, { global: { headers: { Authorization: \`Bearer \${token}\` } } }); }
`,
      "app/api/files/route.ts": `import { admin, asUser, getUserFromRequest } from "@/lib/supabase";
export async function GET(req: Request) {
  const user = await getUserFromRequest(req);
  const path = new URL(req.url).searchParams.get("path")!;
  const mine = await admin().storage.from("documents").createSignedUrl(\`\${user!.id}/\${path}\`, 60);
  const theirs = await asUser("t").storage.from("documents").download(path);
  return Response.json({ mine, theirs });
}
`,
    });
    const model = parseProject(dir);
    const findings = runRules(supabaseStorageRpcPack, model, buildGraph(model), { now: NOW });
    expect(findings).toEqual([]);
  });
});

describe("supabase.storage-policy-without-owner-check", () => {
  function policyFindings(sql: string) {
    const dir = tempProject({ "supabase/migrations/0001.sql": sql });
    const model: ProjectModel = parseProject(dir);
    return runRules([storagePolicyWithoutOwnerCheck], model, buildGraph(model), { now: NOW });
  }

  it("reports write policies that only check the bucket, once per policy", () => {
    const findings =
      policyFindings(`insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
create policy "Avatar images are publicly accessible." on storage.objects for select using (bucket_id = 'avatars');
create policy "Anyone can upload an avatar." on storage.objects for insert with check (bucket_id = 'avatars');
create policy "Owners update avatars" on storage.objects for update using (auth.uid() = owner) with check (bucket_id = 'avatars');
`);
    expect(findings.map((f) => f.title)).toEqual([
      'Storage policy "Anyone can upload an avatar." lets anyone upload into every object in bucket "avatars"',
    ]);
    expect(findings[0]?.entrypoints).toEqual(['Storage API: bucket "avatars"']);
  });

  it("treats public reads as intentional unless the bucket is declared private", () => {
    const quiet = policyFindings(
      `create policy "Public read" on storage.objects for select to anon, authenticated using (bucket_id = 'logos');`,
    );
    expect(quiet).toEqual([]);
    const loud = policyFindings(`insert into storage.buckets (id, name) values ('logos', 'logos');
create policy "Public read" on storage.objects for select using (bucket_id = 'logos');`);
    expect(loud).toHaveLength(1);
    expect(loud[0]?.evidence[0]?.summary).toContain('Bucket "logos" is declared private');
  });

  it("skips path-constrained policies and policies on storage.buckets", () => {
    const findings =
      policyFindings(`create policy "list buckets" on storage.buckets for select using (true);
create policy "public folder" on storage.objects for select to authenticated using (bucket_id = 'docs' and (storage.foldername(name))[1] = 'public');
create policy "tenant folder" on storage.objects for select to authenticated using (bucket_id = 'docs' and public.is_member((storage.foldername(name))[1]::uuid));`);
    expect(findings).toEqual([]);
  });

  it("flags a storage.objects policy that names no bucket at all", () => {
    const findings = policyFindings(
      `create policy "everything" on storage.objects for delete to authenticated using (true);`,
    );
    expect(findings.map((f) => f.title)).toEqual([
      'Storage policy "everything" lets any authenticated user delete every object in every bucket',
    ]);
  });

  it("extracts bucket ids from = and in (...)", () => {
    expect(bucketsIn("bucket_id = 'a' or bucket_id in ('b', 'c')")).toEqual(["a", "b", "c"]);
  });
});

describe("supabase.security-definer-function-without-caller-check", () => {
  function definerFindings(sql: string, patch?: (m: ProjectModel) => void) {
    const dir = tempProject({ "supabase/migrations/0001.sql": sql });
    const model = parseProject(dir);
    patch?.(model);
    return runRules([securityDefinerFunctionWithoutCallerCheck], model, buildGraph(model), {
      now: NOW,
    });
  }

  it("skips trigger functions, other schemas, revoked functions and caller-checking ones", () => {
    const findings = definerFindings(`
create function public.handle_new_user() returns trigger language plpgsql security definer as $$ begin return new; end $$;
create function private.lookup(p uuid) returns uuid language sql security definer as $$ select p $$;
create function public.server_only(p uuid) returns uuid language sql security definer as $$ select p $$;
revoke execute on function public.server_only(uuid) from public, anon, authenticated;
create function public.is_admin() returns boolean language sql security definer as $$ select exists (select 1 from admins where user_id = auth.uid()) $$;
create function public.admin_stats() returns bigint language plpgsql security definer as $$ begin if not public.is_admin() then raise exception 'forbidden'; end if; return 1; end $$;
create function public.leaky(p uuid) returns setof invoices language sql security definer as $$ select * from invoices where tenant_id = p $$;
`);
    expect(findings.map((f) => [f.title, f.severity, f.entrypoints])).toEqual([
      [
        'Anonymous-callable SECURITY DEFINER function "leaky" without a caller check',
        "critical",
        ["POST /rest/v1/rpc/leaky"],
      ],
    ]);
  });

  it("reads functions from model.sqlFunctions only; a model without them knows none", () => {
    const sql = `create function public.leaky(p uuid) returns uuid language sql security definer as $$ select p $$;`;
    const unknown = definerFindings(sql, (m) => {
      delete m.sqlFunctions;
    });
    expect(unknown).toEqual([]);
    const findings = definerFindings(sql, (m) => {
      Object.assign(m, {
        sqlFunctions: [
          {
            name: "from_parser",
            securityDefiner: true,
            checksCaller: false,
            grantedTo: ["authenticated"],
            location: { file: "supabase/migrations/0001.sql", line: 1 },
            returns: "uuid",
          },
        ],
      });
    });
    expect(findings.map((f) => [f.title, f.severity])).toEqual([
      ['SECURITY DEFINER function "from_parser" without a caller check', "high"],
    ]);
  });

  it("reads bucket visibility from model.storageBuckets", () => {
    const dir = tempProject({
      "supabase/migrations/0001.sql": `create policy "Public read" on storage.objects for select using (bucket_id = 'logos');`,
    });
    const model = parseProject(dir);
    Object.assign(model, {
      storageBuckets: [{ id: "logos", public: false, location: { file: "x.sql", line: 3 } }],
    });
    const findings = runRules([storagePolicyWithoutOwnerCheck], model, buildGraph(model), {
      now: NOW,
    });
    expect(findings[0]?.evidence[0]?.summary).toContain(
      'Bucket "logos" is declared private (x.sql:3)',
    );
  });
});

describe("RLS policies scoped through a helper function (rls-policy-without-caller-predicate)", () => {
  const r3 = (dir: string, patch?: (m: ProjectModel) => void) => {
    const model = parseProject(dir);
    patch?.(model);
    return runRules([rlsPolicyWithoutCallerPredicate], model, buildGraph(model), { now: NOW });
  };

  it("does not scope a policy through a helper when the model knows no SQL functions", () => {
    const secure = fixtureDir("029-rls-policy-member-helper", "secure");
    const findings = r3(secure, (m) => {
      delete m.sqlFunctions;
    });
    expect(findings.map((f) => f.ruleId)).toEqual(["supabase.rls-policy-without-caller-predicate"]);
  });

  it("fixture 029: a helper that never reads auth.uid() proves nothing; one that does scopes the policy", () => {
    const expr = "public.is_account_member(account_id)";
    expect(policyScopesToCaller(expr)).toBe(false);
    expect(
      r3(fixtureDir("029-rls-policy-member-helper", "vulnerable")).map((f) => f.title),
    ).toEqual([
      'RLS policy "notes: account members read" on "notes" does not scope rows to the caller',
    ]);
    expect(r3(fixtureDir("029-rls-policy-member-helper", "secure"))).toEqual([]);
  });

  it("reads `col in (select fn())` and helpers the migrations never define", () => {
    const route = `import { createClient } from "@supabase/supabase-js";
export async function GET(req: Request) {
  const token = req.headers.get("authorization")!;
  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!, { global: { headers: { Authorization: token } } });
  const { data } = await supabase.from("deals").select("*");
  return Response.json(data);
}
`;
    const table = `create table public.deals (id uuid primary key, organization_id uuid not null);
alter table public.deals enable row level security;`;
    const scoped = tempProject({
      "app/api/deals/route.ts": route,
      "supabase/migrations/0001.sql": `${table}
create function public.fn_user_org_ids() returns setof uuid language sql stable security definer as $$ select organization_id from public.members where user_id = (select auth.uid()) $$;
create function public.fn_is_platform_admin() returns boolean language sql stable security definer as $$ select coalesce((auth.jwt() ->> 'is_admin')::boolean, false) $$;
create policy "deals: org members" on public.deals for select to authenticated using (organization_id in (select public.fn_user_org_ids()) or public.fn_is_platform_admin());`,
    });
    expect(r3(scoped)).toEqual([]);
    const unknown = tempProject({
      "app/api/deals/route.ts": route,
      "supabase/migrations/0001.sql": `${table}
create policy "deals: org members" on public.deals for select to authenticated using (organization_id in (select public.fn_user_org_ids()));`,
    });
    expect(r3(unknown)).toHaveLength(1);
  });
});
