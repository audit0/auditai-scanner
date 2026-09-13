import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Finding } from "@auditai/core";
import { type ProjectModel, parseProject } from "@auditai/parser";
import { describe, expect, it } from "vitest";
import { deterministicFix, sqlFixFor } from "./sql-fixes.js";

/**
 * Every fix here has to be a migration a person can read and apply as it stands. The tests check
 * the SQL itself, not a shape: a wrong REVOKE signature or a policy tied to the wrong column is
 * worse than no proposal at all.
 */

const SQL = `create table public.notes (id uuid primary key, user_id uuid not null, body text);
create table public.stats (id uuid primary key, total integer);
alter table public.stats enable row level security;
create policy "stats: anyone writes" on public.stats for update to anon, authenticated using (true);
create function public.bump(p_id bigint, amount integer default 1)
returns void language plpgsql security definer as $$
begin update public.stats set total = total + amount where id = p_id; end;
$$;
create function public.tally() returns integer language sql security definer as $$
  select count(*)::int from public.notes
$$;
`;

function model(sql = SQL): ProjectModel {
  const dir = mkdtempSync(join(tmpdir(), "auditai-fixes-"));
  const rel = "supabase/migrations/0001_init.sql";
  mkdirSync(dirname(join(dir, rel)), { recursive: true });
  writeFileSync(join(dir, rel), sql);
  return parseProject(dir, { sqlDirs: ["supabase/migrations"] });
}

function finding(ruleId: string, data: Record<string, unknown>): Finding {
  return {
    id: "AUDIT-001",
    ruleId,
    title: "t",
    status: "likely",
    severity: "high",
    confidence: 0.9,
    entrypoints: [],
    sources: [],
    sinks: [],
    path: [],
    evidence: [{ kind: "rule", summary: "s", data }],
    createdAt: "2026-09-13T10:11:12Z",
    updatedAt: "2026-09-13T10:11:12Z",
  };
}

describe("SECURITY DEFINER function", () => {
  it("revokes with the exact signature, including defaults and no arguments", () => {
    const m = model();
    const withArgs = sqlFixFor(
      finding("supabase.security-definer-function-without-caller-check", { function: "bump" }),
      m,
    );
    expect(withArgs?.sql).toContain(
      "revoke execute on function public.bump(bigint, integer) from public, anon, authenticated;",
    );
    const noArgs = sqlFixFor(
      finding("supabase.security-definer-function-without-caller-check", { function: "tally" }),
      m,
    );
    expect(noArgs?.sql).toContain("revoke execute on function public.tally() from");
  });

  it("says why revoking from PUBLIC alone is not enough", () => {
    const fix = sqlFixFor(
      finding("supabase.security-definer-function-without-caller-check", { function: "tally" }),
      model(),
    );
    expect(fix?.rationale).toContain("anon and authenticated directly");
  });

  it("runs a reading function as the caller when every table it reads is policed by RLS", () => {
    const sql = `create table public.invoices (id uuid primary key, tenant_id uuid not null, amount integer);
alter table public.invoices enable row level security;
create policy "invoices: tenant reads" on public.invoices for select to authenticated using (true);
create table public.drafts (id uuid primary key, amount integer);
alter table public.drafts enable row level security;
create function public.invoice_total(invoice_id uuid) returns bigint language sql security definer as $$
  select sum(amount) from public.invoices where id = invoice_id
$$;
create function public.draft_total(draft_id uuid) returns bigint language sql security definer as $$
  select sum(amount) from public.drafts where id = draft_id
$$;
create function public.user_count() returns bigint language sql security definer as $$
  select count(*) from auth.users
$$;
create function public.touch(invoice_id uuid) returns void language sql security definer as $$
  select 1 from public.invoices where id = invoice_id
$$;
`;
    const rule = "supabase.security-definer-function-without-caller-check";
    const invoker = sqlFixFor(finding(rule, { function: "invoice_total" }), model(sql));
    expect(invoker?.sql).toContain("alter function public.invoice_total(uuid) security invoker;");
    expect(invoker?.sql).not.toContain("revoke");
    expect(invoker?.rationale).toContain("public.invoices");
    // RLS on but no policy: running as the caller would return nothing, so the app would break.
    expect(sqlFixFor(finding(rule, { function: "draft_total" }), model(sql))?.sql).toContain(
      "revoke execute on function public.draft_total(uuid)",
    );
    // A table the schema does not have: we cannot tell what the caller may read.
    expect(sqlFixFor(finding(rule, { function: "user_count" }), model(sql))?.sql).toContain(
      "revoke execute",
    );
    // Nothing is returned, so nothing tells a reading caller from a writing one.
    expect(sqlFixFor(finding(rule, { function: "touch" }), model(sql))?.sql).toContain(
      "revoke execute",
    );
  });

  it("proposes nothing for a function the migrations do not declare", () => {
    const fix = sqlFixFor(
      finding("supabase.security-definer-function-without-caller-check", { function: "ghost" }),
      model(),
    );
    expect(fix).toBeNull();
  });
});

describe("row level security", () => {
  it("enables RLS and scopes the policies to the owner column", () => {
    const fix = sqlFixFor(finding("supabase.table-without-rls", { table: "notes" }), model());
    expect(fix?.sql).toContain("alter table public.notes enable row level security;");
    expect(fix?.sql).toContain("using (user_id = (select auth.uid()))");
    expect(fix?.sql).toContain("with check (user_id = (select auth.uid()))");
  });

  it("writes no policy when no column ties a row to a person", () => {
    const fix = sqlFixFor(finding("supabase.table-without-rls", { table: "stats" }), model());
    expect(fix?.sql).toContain("alter table public.stats enable row level security;");
    expect(fix?.sql).not.toContain("create policy");
    expect(fix?.sql).toContain("no policy is proposed");
  });

  it("only turns RLS on when the table already carries policies", () => {
    const fix = sqlFixFor(
      finding("supabase.policies-without-rls-enabled", { table: "notes" }),
      model(),
    );
    expect(fix?.sql).toContain("alter table public.notes enable row level security;");
    expect(fix?.sql).not.toContain("create policy");
    expect(fix?.sql).toContain("have never run");
  });
});

describe("open write policy", () => {
  it("replaces the policy with one tied to the caller, keeping the command", () => {
    const sql = `${SQL}create policy "notes: anyone updates" on public.notes for update to anon using (true);\n`;
    const fix = sqlFixFor(
      finding("supabase.anon-write-policy", {
        table: "notes",
        policy: "notes: anyone updates",
        command: "update",
      }),
      model(sql),
    );
    expect(fix?.sql).toContain('drop policy "notes: anyone updates" on public.notes;');
    expect(fix?.sql).toContain("for update to authenticated");
    expect(fix?.sql).toContain("using (user_id = (select auth.uid()));");
  });

  it("uses with check for an insert policy", () => {
    const fix = sqlFixFor(
      finding("supabase.anon-write-policy", {
        table: "notes",
        policy: "notes: anyone inserts",
        command: "insert",
      }),
      model(),
    );
    expect(fix?.sql).toContain("for insert to authenticated");
    expect(fix?.sql).toContain("with check (user_id = (select auth.uid()));");
    expect(fix?.sql).not.toContain("using (");
  });

  it("drops the policy when the table has no owner column, and says so", () => {
    const fix = sqlFixFor(
      finding("supabase.anon-write-policy", {
        table: "stats",
        policy: "stats: anyone writes",
        command: "update",
      }),
      model(),
    );
    expect(fix?.sql).toContain('drop policy "stats: anyone writes" on public.stats;');
    expect(fix?.sql).not.toContain("create policy");
    expect(fix?.rationale).toContain("Nothing in the table identifies an owner");
  });

  it("escapes a quote in a policy name", () => {
    const fix = sqlFixFor(
      finding("supabase.anon-write-policy", {
        table: "notes",
        policy: 'the "open" one',
        command: "update",
      }),
      model(),
    );
    expect(fix?.sql).toContain('drop policy "the ""open"" one" on public.notes;');
  });
});

describe("as a FixProposal", () => {
  it("adds one migration file named after the finding's day", () => {
    const fix = deterministicFix(
      finding("supabase.table-without-rls", { table: "notes" }),
      model(),
      "supabase/migrations",
    );
    expect(fix?.touchedFiles).toEqual([
      "supabase/migrations/20260913101112_fix_enable_rls_notes.sql",
    ]);
    expect(fix?.diff).toContain("new file mode 100644");
    expect(fix?.diff).toContain("+alter table public.notes enable row level security;");
    // Every line of the body is an addition: the diff creates a file and touches nothing else.
    const body = fix?.diff.split("\n").filter((l) => l.startsWith("+") && !l.startsWith("+++"));
    expect(body?.length).toBeGreaterThan(3);
  });

  it("proposes nothing for a finding whose fix is in application code", () => {
    expect(
      deterministicFix(
        finding("supabase.service-role-object-access-without-tenant-scope", { table: "notes" }),
        model(),
      ),
    ).toBeNull();
  });
});

describe("tenant-owned tables", () => {
  const TENANT_SQL = `create table public.invoices (id uuid primary key, tenant_id uuid not null, total integer);
create table public.orgs_notes (id uuid primary key, organization_id uuid not null, created_by uuid not null);
`;

  it("never compares a tenant column with auth.uid() when enabling RLS", () => {
    const fix = sqlFixFor(
      finding("supabase.table-without-rls", { table: "invoices" }),
      model(TENANT_SQL),
    );
    expect(fix?.sql).toContain("alter table public.invoices enable row level security;");
    expect(fix?.sql).not.toContain("tenant_id = (select auth.uid())");
    expect(fix?.sql).not.toContain("create policy");
    expect(fix?.sql).toContain("no policy is proposed");
    expect(fix?.sql).toContain("where user_id = (select auth.uid())");
  });

  it("prefers the person column when a table has both", () => {
    const fix = sqlFixFor(
      finding("supabase.table-without-rls", { table: "orgs_notes" }),
      model(TENANT_SQL),
    );
    expect(fix?.sql).toContain("using (created_by = (select auth.uid()))");
  });

  it("drops an open write policy on a tenant table without inventing a predicate", () => {
    const fix = sqlFixFor(
      finding("supabase.anon-write-policy", {
        table: "invoices",
        policy: "open",
        command: "update",
      }),
      model(TENANT_SQL),
    );
    expect(fix?.sql).toContain('drop policy "open" on public.invoices;');
    expect(fix?.sql).not.toContain("create policy");
    expect(fix?.rationale).toContain("belong to a tenant through tenant_id");
  });
});

/**
 * A finding reaches the sandbox as JSON, so every name a migration contains has to come from the
 * schema the fixer parsed, never from the finding. These are the cases that would otherwise put a
 * caller's string into SQL.
 */
describe("names come from the schema, not from the finding", () => {
  it("proposes nothing for a table the migrations do not define", () => {
    expect(
      sqlFixFor(finding("supabase.table-without-rls", { table: "ghost" }), model()),
    ).toBeNull();
    expect(
      sqlFixFor(
        finding("supabase.anon-write-policy", { table: "ghost", policy: "p", command: "update" }),
        model(),
      ),
    ).toBeNull();
  });

  it("refuses a name that is not an identifier, even if it contains a real table", () => {
    const evil = "notes; drop table public.notes; --";
    expect(sqlFixFor(finding("supabase.table-without-rls", { table: evil }), model())).toBeNull();
    expect(
      sqlFixFor(
        finding("supabase.security-definer-function-without-caller-check", {
          function: "tally(); drop table public.notes; --",
        }),
        model(),
      ),
    ).toBeNull();
  });

  it("refuses an unknown policy command", () => {
    expect(
      sqlFixFor(
        finding("supabase.anon-write-policy", {
          table: "notes",
          policy: "p",
          command: "update to anon using (true); drop table notes; --",
        }),
        model(),
      ),
    ).toBeNull();
  });

  it("accepts the schema-qualified spelling and writes the schema's own name", () => {
    const fix = sqlFixFor(
      finding("supabase.table-without-rls", { table: "public.notes" }),
      model(),
    );
    expect(fix?.sql).toContain("alter table public.notes enable row level security;");
    expect(fix?.file).toBe("fix_enable_rls_notes.sql");
  });
});
