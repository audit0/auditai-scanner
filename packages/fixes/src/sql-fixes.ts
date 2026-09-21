import type { Finding, FixProposal } from "@auditai/core";
import type { ProjectModel, RlsTable, SqlFunctionInfo } from "@auditai/parser";

/**
 * Minimal fixes that need no model: every one of them is a migration a person can read in a few
 * seconds, and every one follows from the schema the parser already has. Nothing here edits an
 * existing migration — Postgres state is the sum of migrations, so the fix is always a new file
 * appended at the end, which is also what the Supabase CLI expects.
 *
 * A deterministic fix is a proposal, never an applied change: it says what to add, why, and what
 * it does not cover. Rules whose fix depends on application code (a missing tenant filter in a
 * route) are deliberately absent — guessing an edit there would be worse than saying nothing.
 */

/** Rules a deterministic fix exists for. Everything else returns null. */
export const FIXABLE_RULES: readonly string[] = [
  "supabase.security-definer-function-without-caller-check",
  "supabase.table-without-rls",
  "supabase.policies-without-rls-enabled",
  "supabase.anon-write-policy",
  "supabase.rls-policy-trusts-user-metadata",
];

export interface SqlFix {
  /** File name to create under the migrations directory, without a path. */
  file: string;
  /** The migration body, ending with a newline. */
  sql: string;
  summary: string;
  rationale: string;
}

/**
 * Columns that hold the id of one signed-in person, so `column = auth.uid()` is the right predicate.
 * Most specific first.
 */
const PERSON_COLUMNS = ["user_id", "owner_id", "profile_id", "author_id", "created_by"];

/**
 * Columns that hold a tenant, organization or team id. Comparing one of these with `auth.uid()`
 * is wrong: a tenant id is not a user id, so such a policy locks every member out of their own
 * rows. The right predicate is a membership lookup that only this schema can say, so for these
 * tables no policy is proposed and the migration says why.
 */
const TENANT_COLUMNS = [
  "account_id",
  "tenant_id",
  "organization_id",
  "org_id",
  "workspace_id",
  "team_id",
];

/** Roles Supabase exposes through PostgREST. Revoking from PUBLIC alone leaves these in place. */
const API_ROLES = "public, anon, authenticated";

/** A bare or schema-qualified Postgres identifier: `notes`, `public.notes`, `storage.objects`. */
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_$]*(\.[A-Za-z_][A-Za-z0-9_$]*)?$/;

/**
 * The table the schema actually has under this name, or undefined. Every name that ends up in a
 * migration comes from here, not from the finding: a finding crosses JSON on its way to the
 * sandbox, and a name that is not a table of this schema must never be written into SQL.
 */
function table(model: ProjectModel, name: string | undefined): RlsTable | undefined {
  if (!name || !IDENTIFIER.test(name)) return undefined;
  const key = name.toLowerCase().replace(/^public\./, "");
  const t = model.tables.find((x) => x.table.toLowerCase() === key);
  return t && IDENTIFIER.test(t.table) ? t : undefined;
}

/**
 * The predicate that ties a row to the caller through this column, or null when its type cannot hold
 * a user id. `auth.uid()` is a uuid: a uuid column compares directly, a text column through a cast,
 * and anything else (a bigint `user_id` keyed to a profiles table) would make the migration fail.
 * A column whose type the source does not say is taken as uuid, the Supabase convention.
 */
function ownerPredicate(t: RlsTable, column: string): string | null {
  const type = (t.columnInfo ?? []).find((c) => c.name === column)?.type ?? "unknown";
  if (type === "uuid" || type === "unknown") return `${column} = (select auth.uid())`;
  if (type === "text" || /^(varchar|character varying)\b/.test(type))
    return `${column} = (select auth.uid())::text`;
  return null;
}

/** How a row of this table belongs to someone, as far as its columns tell. */
type Ownership =
  | { kind: "person"; column: string }
  | { kind: "tenant"; column: string }
  | { kind: "none" };

function ownershipOf(t: RlsTable | undefined): Ownership {
  if (!t) return { kind: "none" };
  const cols = t.columns.map((c) => c.toLowerCase());
  for (const c of PERSON_COLUMNS)
    if (cols.includes(c) && ownerPredicate(t, c) !== null) return { kind: "person", column: c };
  for (const c of TENANT_COLUMNS) if (cols.includes(c)) return { kind: "tenant", column: c };
  // A key into auth.users is a person whatever it is called: `profiles.id` is the usual one. Only
  // when there is exactly one, so that a table with both an author and a reviewer gets no guess.
  const toUsers = (t.columnInfo ?? []).filter(
    (c) =>
      c.references?.table === "auth.users" && (c.references.column ?? "id") === "id" && !c.sqlName,
  );
  const only = toUsers.length === 1 ? toUsers[0] : undefined;
  if (only && ownerPredicate(t, only.name) !== null) return { kind: "person", column: only.name };
  return { kind: "none" };
}

/** The comment a migration carries when the table's owner is a tenant, not a person. */
function tenantNote(full: string, column: string): string {
  return `-- ${full} belongs to a tenant through ${column}, not to one person. Comparing ${column} with\n-- auth.uid() would lock every member out of their own rows, so no policy is proposed here.\n-- Write one that looks the caller's membership up, for example:\n--   using (${column} in (select ${column} from public.<memberships> where user_id = (select auth.uid())))\n`;
}

/** `public.orders` for a bare name, `storage.objects` kept as it is. */
function qualified(name: string): string {
  return name.includes(".") ? name : `public.${name}`;
}

function quoteIdent(name: string): string {
  return `"${name.replace(/"/g, '""')}"`;
}

/** A name as SQL must spell it: bare when Postgres would fold it to itself, quoted otherwise. */
function sqlIdent(name: string): string {
  return /^[a-z_][a-z0-9_$]*$/.test(name) ? name : quoteIdent(name);
}

/** The relation as SQL names it: `public."Post"` for Prisma's `Post`, `public.orders` otherwise. */
function relationSql(t: RlsTable): string {
  if (t.table.includes(".")) return t.table;
  return `public.${sqlIdent(t.sqlName ?? t.table)}`;
}

/**
 * Database text placed in a `--` comment: one line, whatever the name holds. A newline in a policy
 * name would end the comment and turn the rest of the name into a statement of the migration.
 */
function commentText(s: string): string {
  return [...s].map((c) => (isControl(c) ? "?" : c)).join("");
}

/** C0 and C1 controls and the Unicode line and paragraph separators: characters that break a line. */
function isControl(c: string): boolean {
  const n = c.charCodeAt(0);
  return n < 0x20 || (n >= 0x7f && n <= 0x9f) || n === 0x2028 || n === 0x2029;
}

/**
 * A policy name a migration can carry: short and on one line. Postgres allows a newline inside a
 * quoted name, but no real policy has one, and a migration read line by line would split it.
 */
function policyNameOk(name: string): boolean {
  return name.length > 0 && name.length <= 200 && ![...name].some(isControl);
}

/**
 * An argument list as Postgres prints it for a function's identity, if it looks like one: names,
 * types, quotes, brackets and commas, balanced. Anything else (a `;`, a comment) is not what the
 * catalog returns, and is never written into a statement.
 */
function identityOk(args: string): boolean {
  if (!/^[\w$\s,."[\]()]*$/.test(args)) return false;
  if ((args.match(/"/g) ?? []).length % 2 !== 0) return false;
  let depth = 0;
  for (const c of args) {
    depth += c === "(" ? 1 : c === ")" ? -1 : 0;
    if (depth < 0) return false;
  }
  return depth === 0;
}

/**
 * The function a finding is about. Overloads share a name, so the finding's own identity (the
 * argument list the database printed) picks the one it judged; without it, the first by name.
 */
function fn(
  model: ProjectModel,
  name: string | undefined,
  identity?: string,
): SqlFunctionInfo | undefined {
  if (!name || !IDENTIFIER.test(name)) return undefined;
  const key = name.toLowerCase().replace(/^public\./, "");
  const f = (model.sqlFunctions ?? []).find(
    (x) => x.name.toLowerCase() === key && (identity === undefined || x.identity === identity),
  );
  return f && IDENTIFIER.test(f.name) ? f : undefined;
}

/** `public.f(uuid, text)` — the signature REVOKE needs; without argument types it is ambiguous. */
function signatureOf(f: SqlFunctionInfo): string {
  const name = f.name.includes(".") ? f.name : `public.${sqlIdent(f.sqlName ?? f.name)}`;
  // The database's own identity list is exact (quoted enum types, `character varying`); the list
  // read from migrations is lowercased and simplified, and used only when that is all there is.
  if (f.identity !== undefined && identityOk(f.identity)) return `${name}(${f.identity})`;
  return f.args === undefined ? `${name}(...)` : `${name}(${f.args})`;
}

const COMMANDS = new Set(["select", "insert", "update", "delete", "all"]);

const HEADER = (title: string): string =>
  `-- ${commentText(title)}\n-- Proposed by Audit AI. Read it, then apply it with the rest of your migrations.\n`;

// ---------------------------------------------------------------------------------------------

/**
 * The tables a function reads when every one of them is a table of this schema with row level
 * security on and at least one policy; otherwise null. Only then can the function run with the
 * caller's rights without losing what the app itself reads through it: the policies already decide
 * what each caller may see. A relation the schema does not have (auth.users, a CTE, a view) means
 * we cannot tell, and the fix stays a revoke.
 */
function policedTables(f: SqlFunctionInfo, model: ProjectModel): string[] | null {
  const names = f.tables ?? [];
  if (names.length === 0) return null;
  const out: string[] = [];
  for (const n of names) {
    const t = table(model, n);
    if (!t?.rlsEnabled || t.policies.length === 0) return null;
    out.push(qualified(t.table));
  }
  return out;
}

function sqlFunctionFix(finding: Finding, model: ProjectModel): SqlFix | null {
  const data = finding.evidence[0]?.data ?? {};
  const name = data.function;
  const identity = typeof data.identity === "string" ? data.identity : undefined;
  const f = fn(model, typeof name === "string" ? name : undefined, identity);
  if (!f) return null;
  const sig = signatureOf(f);
  const ambiguous = sig.endsWith("(...)");
  const policed = f.returns !== undefined && f.returns !== "void" ? policedTables(f, model) : null;
  if (policed && !ambiguous) {
    return {
      file: `fix_security_invoker_${f.name.replace(/[^a-z0-9]+/gi, "_").toLowerCase()}.sql`,
      sql: [
        HEADER(`Run ${f.name} with the caller's rights, so row level security applies inside it`),
        `-- It reads ${policed.join(", ")}, and each of them has row level security with policies.\n`,
        `alter function ${sig} security invoker;\n`,
      ].join(""),
      summary: `Run ${f.name} with the caller's rights (security invoker)`,
      rationale: `${f.name} only reads tables that already have row level security with policies (${policed.join(", ")}), so running it with the caller's rights lets those policies decide what it returns, and calls from your app keep working. If it must keep its owner's rights on purpose (for example it counts rows a caller may not see), revoke execute from public, anon and authenticated instead, or add a caller check inside the body.`,
    };
  }
  const body = [
    HEADER(`Stop anon and authenticated from calling ${f.name} directly`),
    ambiguous
      ? "-- The argument types could not be read from the migrations; put the real signature in\n-- place of (...) before applying. `\\df public.*` in psql prints it.\n"
      : "",
    `revoke execute on function ${sig} from ${API_ROLES};\n`,
    "-- Leave this line out if nothing calls the function with the service role.\n",
    `grant execute on function ${sig} to service_role;\n`,
  ].join("");
  return {
    file: `fix_revoke_execute_${f.name.replace(/[^a-z0-9]+/gi, "_").toLowerCase()}.sql`,
    sql: body,
    summary: `Revoke execute on ${f.name} from the API roles`,
    rationale:
      "The function runs as its creator, so row level security does not apply inside it, and Supabase grants execute on new functions in schema public to anon and authenticated directly. Revoking from PUBLIC alone does not remove those grants, which is why a function that looks locked down is still callable with the public key. If a browser is supposed to call it, do not apply this: add a caller check inside the body instead (`where owner_id = (select auth.uid())`).",
  };
}

function enableRlsFix(finding: Finding, model: ProjectModel, withPolicy: boolean): SqlFix | null {
  const asked = finding.evidence[0]?.data?.table;
  const t = table(model, typeof asked === "string" ? asked : undefined);
  if (!t) return null;
  const name = t.table;
  const full = relationSql(t);
  const own = ownershipOf(t);
  const owner = own.kind === "person" ? ownerPredicate(t, own.column) : null;
  const lines = [HEADER(`Turn on row level security for ${full}`)];
  lines.push(`alter table ${full} enable row level security;\n`);
  if (withPolicy) {
    if (own.kind === "tenant") {
      lines.push(`\n${tenantNote(full, own.column)}`);
    } else if (owner) {
      lines.push(
        `\ncreate policy "${name}: owner reads" on ${full}\n  for select to authenticated\n  using (${owner});\n`,
        `\ncreate policy "${name}: owner writes" on ${full}\n  for all to authenticated\n  using (${owner})\n  with check (${owner});\n`,
      );
    } else {
      lines.push(
        `\n-- No column of ${full} ties a row to a person (looked for ${PERSON_COLUMNS.slice(0, 4).join(", ")}…),\n-- so no policy is proposed: with RLS on and no policy the table is readable only with the\n-- service role, which is the safe default. Add a policy once you decide who owns a row.\n`,
      );
    }
  } else {
    lines.push(
      `\n-- The policies this table already has start applying the moment row level security is on;\n-- read them once before applying, because until now they have never run.\n`,
    );
  }
  return {
    file: `fix_enable_rls_${name.replace(/[^a-z0-9]+/gi, "_").toLowerCase()}.sql`,
    sql: lines.join(""),
    summary: `Enable row level security on ${full}`,
    rationale: withPolicy
      ? "Without row level security the anon key reads and writes every row of the table through PostgREST. Turning it on denies everything by default, so apply this together with a policy, and check that your own server code uses the service role where it needs full access."
      : "The table already carries policies, which is what makes this a defect rather than a choice: they have no effect until row level security is on. Read them once before applying — they have never run, so they may not say what their author believed.",
  };
}

function anonWriteFix(finding: Finding, model: ProjectModel): SqlFix | null {
  const data = finding.evidence[0]?.data ?? {};
  const policy = data.policy;
  const command = data.command;
  const t = table(model, typeof data.table === "string" ? data.table : undefined);
  if (!t || typeof policy !== "string" || !policyNameOk(policy)) return null;
  if (command !== undefined && !COMMANDS.has(String(command))) return null;
  const name = t.table;
  const full = relationSql(t);
  const own = ownershipOf(t);
  const owner = own.kind === "person" ? ownerPredicate(t, own.column) : null;
  const cmd = typeof command === "string" ? command : "all";
  const safeName = policy.replace(/"/g, '""');
  const lines = [HEADER(`Close the open write policy "${policy}" on ${full}`)];
  if (own.kind === "tenant") {
    lines.push(`drop policy "${safeName}" on ${full};\n`, `\n${tenantNote(full, own.column)}`);
  } else if (owner) {
    lines.push(
      `drop policy "${safeName}" on ${full};\n`,
      `\ncreate policy "${safeName}" on ${full}\n  for ${cmd} to authenticated\n`,
      // USING decides which rows a caller may touch, WITH CHECK what a row may become: an update
      // needs both, or the owner could hand a row to someone else.
      cmd === "insert"
        ? `  with check (${owner});\n`
        : cmd === "delete"
          ? `  using (${owner});\n`
          : `  using (${owner})\n  with check (${owner});\n`,
    );
  } else {
    lines.push(
      `-- No column of ${full} ties a row to a person, so there is nothing to compare the caller\n-- with. Either add one, or take the policy away and let your server write the table with the\n-- service role after it has checked the caller itself.\n`,
      `drop policy "${safeName}" on ${full};\n`,
    );
  }
  return {
    file: `fix_policy_${name.replace(/[^a-z0-9]+/gi, "_").toLowerCase()}_${cmd}.sql`,
    sql: lines.join(""),
    summary: `Tie the write policy on ${full} to the caller`,
    rationale: owner
      ? `The policy decides with a tautology and is open to anon, so anyone holding the public key can write ${full} straight through PostgREST. The replacement keeps the same command and ties the row to the signed-in caller (${owner}). If this table is meant to accept rows from strangers (a contact form, a newsletter), keep the insert open but give it a predicate on the row's shape and a rate limit.`
      : own.kind === "tenant"
        ? `The policy decides with a tautology and is open to anon, so anyone holding the public key can write ${full} straight through PostgREST. Rows belong to a tenant through ${own.column}, and only your schema knows how a user becomes a member, so the migration removes the open policy and shows the shape of the membership check to write instead.`
        : `The policy decides with a tautology and is open to anon, so anyone holding the public key can write ${full} straight through PostgREST. Nothing in the table identifies an owner, so the honest fix is to remove the policy and write the table from your server after it has checked the caller.`,
  };
}

function userMetadataFix(finding: Finding, model: ProjectModel): SqlFix | null {
  const data = finding.evidence[0]?.data ?? {};
  const policy = data.policy;
  const t = table(model, typeof data.table === "string" ? data.table : undefined);
  if (!t || typeof policy !== "string" || !policyNameOk(policy)) return null;
  const name = t.table;
  const full = relationSql(t);
  const quoted = commentText(policy.replace(/"/g, '""'));
  return {
    file: `fix_policy_${name.replace(/[^a-z0-9]+/gi, "_").toLowerCase()}_app_metadata.sql`,
    sql: [
      HEADER(`Stop the policy "${policy}" on ${full} from trusting user_metadata`),
      "-- Re-create the policy with the claim read from app_metadata, which only the service role\n",
      "-- writes. Copy the predicate from your own migration and change the one word: replace\n",
      "--   (select auth.jwt()) -> 'user_metadata' ->> '<claim>'\n",
      "-- with\n",
      "--   (select auth.jwt()) -> 'app_metadata' ->> '<claim>'\n",
      `--\n-- drop policy "${quoted}" on ${full};\n`,
      `-- create policy "${quoted}" on ${full} ... using (...);\n`,
      "\n-- Then set the claim where the user cannot reach it, from a server with the service role:\n",
      "--   await admin.auth.admin.updateUserById(id, { app_metadata: { is_admin: true } });\n",
    ].join(""),
    summary: `Move the claim behind "${policy}" from user_metadata to app_metadata`,
    rationale:
      "user_metadata is written by the user themselves with supabase.auth.updateUser({ data }), and it is copied into their next access token without review, so a policy that reads it grants itself. app_metadata can only be set with the service role. This fix is a template rather than a finished statement: the predicate belongs to your policy, and moving the claim only helps once something server-side actually sets app_metadata.",
  };
}

// ---------------------------------------------------------------------------------------------

/** The deterministic fix for a finding, or null when its fix depends on application code. */
export function sqlFixFor(finding: Finding, model: ProjectModel): SqlFix | null {
  switch (finding.ruleId) {
    case "supabase.security-definer-function-without-caller-check":
      return sqlFunctionFix(finding, model);
    case "supabase.table-without-rls":
      return enableRlsFix(finding, model, true);
    case "supabase.policies-without-rls-enabled":
      return enableRlsFix(finding, model, false);
    case "supabase.anon-write-policy":
      return anonWriteFix(finding, model);
    case "supabase.rls-policy-trusts-user-metadata":
      return userMetadataFix(finding, model);
    default:
      return null;
  }
}

/** A unified diff that adds one file, the shape `git apply` accepts. */
function addFileDiff(path: string, body: string): string {
  const lines = body.replace(/\n$/, "").split("\n");
  return [
    `diff --git a/${path} b/${path}`,
    "new file mode 100644",
    "--- /dev/null",
    `+++ b/${path}`,
    `@@ -0,0 +1,${lines.length} @@`,
    ...lines.map((l) => `+${l}`),
    "",
  ].join("\n");
}

/**
 * The deterministic fix as a FixProposal: a new migration, the diff that creates it, and the
 * reasoning in plain words. `migrationsDir` is where this project keeps its migrations.
 */
export function deterministicFix(
  finding: Finding,
  model: ProjectModel,
  migrationsDir = "supabase/migrations",
): FixProposal | null {
  const fix = sqlFixFor(finding, model);
  if (!fix) return null;
  const stamp = (finding.createdAt ?? "").replace(/\D/g, "").slice(0, 14) || "00000000000000";
  const path = `${migrationsDir}/${stamp}_${fix.file}`;
  return {
    summary: fix.summary,
    diff: addFileDiff(path, fix.sql),
    touchedFiles: [path],
    rationale: fix.rationale,
  };
}
