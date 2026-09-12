import type { FileRef, SqlFunctionInfo } from "./model.js";
import {
  identOf,
  isPublicSchema,
  normalizeType,
  type QualifiedName,
  qualifiedKey,
  readQualifiedName,
} from "./sql-columns.js";
import {
  groupEnd,
  isPunct,
  isWord,
  maskSqlComments,
  type SqlStatement,
  splitTopLevelTokens,
  type Token,
} from "./sql-lexer.js";

/**
 * SQL functions from migrations: SECURITY DEFINER, whether the body looks at the caller, and who
 * may execute them after GRANT/REVOKE.
 *
 * Privilege assumptions (Postgres + Supabase defaults, applied to migrations run as `postgres`):
 * - Postgres grants EXECUTE on every new function to PUBLIC. Only a global
 *   `ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC` (no IN SCHEMA) changes that.
 * - Supabase's default privileges grant EXECUTE on new functions in schema `public` to `anon` and
 *   `authenticated` directly, so `REVOKE ... FROM PUBLIC` alone does not lock them out either.
 * - So a function in `public` starts as executable by anon and authenticated. It stops being callable
 *   by them only when both PUBLIC and the role itself are revoked: `grantedTo` lists anon and
 *   authenticated while PUBLIC still holds EXECUTE, and lists "public" only after an explicit
 *   `GRANT ... TO PUBLIC`.
 * - Functions in other schemas are not exposed through the Data API: they start with no roles and only
 *   explicit grants add some.
 * - CREATE OR REPLACE keeps existing privileges; DROP FUNCTION forgets them. Overloads share one entry.
 */

interface Acl {
  /** PUBLIC holds EXECUTE (by default or by grant). */
  publicExec: boolean;
  /** PUBLIC was granted explicitly. */
  explicitPublic: boolean;
  /** Roles granted directly, in grant order. */
  roles: string[];
}

interface FunctionState {
  schema: string | null;
  name: string;
  securityDefiner: boolean;
  returns: string | null;
  /** Argument types as written (`uuid, integer`), empty for none, null when unreadable. */
  args: string | null;
  /** Body with comments blanked. */
  body: string;
  directCheck: boolean;
  acl: Acl;
  location: FileRef;
}

export interface FunctionRegistry {
  byKey: Map<string, FunctionState>;
  /** Global default: PUBLIC gets EXECUTE on new functions. */
  defaultPublic: boolean;
  /** Global default grants (ALTER DEFAULT PRIVILEGES without IN SCHEMA). */
  defaultRoles: string[];
  /** Per-schema default grants for schema public (Supabase: anon, authenticated). */
  publicSchemaRoles: string[];
  /** Per-schema GRANT ... TO PUBLIC for schema public. */
  publicSchemaPublic: boolean;
}

export function newFunctionRegistry(): FunctionRegistry {
  return {
    byKey: new Map(),
    defaultPublic: true,
    defaultRoles: [],
    publicSchemaRoles: ["anon", "authenticated"],
    publicSchemaPublic: false,
  };
}

/** Direct reads of the caller's identity. auth.role() is deliberately absent: it names a role, not a caller. */
const CALLER_CHECKS = [
  /"?\bauth"?\s*\.\s*"?(?:uid|jwt|email)"?\s*\(\s*\)/i,
  /\bcurrent_setting\s*\(\s*'request\.jwt/i,
];

const OPTION_WORDS = new Set([
  "language",
  "as",
  "security",
  "external",
  "immutable",
  "stable",
  "volatile",
  "strict",
  "called",
  "cost",
  "rows",
  "parallel",
  "leakproof",
  "window",
  "support",
  "transform",
  "return",
  "set",
]);

function isOptionStart(tokens: readonly Token[], i: number): boolean {
  const t = tokens[i];
  if (t?.kind !== "word") return false;
  if (OPTION_WORDS.has(t.value)) return true;
  if (t.value === "not") return isWord(tokens[i + 1], "leakproof");
  if (t.value === "begin") return isWord(tokens[i + 1], "atomic");
  if (t.value === "returns") return isWord(tokens[i + 1], "null");
  return false;
}

function normalizeReturns(tokens: readonly Token[]): string | null {
  if (tokens.length === 0) return null;
  if (isWord(tokens[0], "table")) return "table";
  if (isWord(tokens[0], "setof")) return `setof ${normalizeType(tokens.slice(1)).type}`;
  return normalizeType(tokens).type;
}

function addRole(list: string[], role: string): void {
  if (!list.includes(role)) list.push(role);
}

function removeRole(list: string[], role: string): void {
  const i = list.indexOf(role);
  if (i >= 0) list.splice(i, 1);
}

function initialAcl(reg: FunctionRegistry, schema: string | null): Acl {
  if (!isPublicSchema(schema)) {
    return { publicExec: false, explicitPublic: false, roles: [...reg.defaultRoles] };
  }
  const roles = [...reg.defaultRoles];
  for (const r of reg.publicSchemaRoles) addRole(roles, r);
  return { publicExec: reg.defaultPublic || reg.publicSchemaPublic, explicitPublic: false, roles };
}

/** CREATE [OR REPLACE] FUNCTION. Procedures are not callable through PostgREST and are skipped. */
export function applyCreateFunction(reg: FunctionRegistry, stmt: SqlStatement, file: string): void {
  const tk = stmt.tokens;
  let i = 1;
  if (isWord(tk[i], "or") && isWord(tk[i + 1], "replace")) i += 2;
  if (!isWord(tk[i], "function")) return;
  const q = readQualifiedName(tk, i + 1);
  if (!q || !isPunct(tk[q.next], "(")) return;
  const argsEnd = groupEnd(tk, q.next);
  const args = argumentTypes(stmt, tk, q.next, argsEnd);
  i = argsEnd + 1;
  let securityDefiner = false;
  let returns: string | null = null;
  let body = "";
  while (i < tk.length) {
    const t = tk[i];
    if (isWord(t, "returns") && isWord(tk[i + 1], "null")) {
      i += 5; // RETURNS NULL ON NULL INPUT
    } else if (isWord(t, "returns")) {
      let j = i + 1;
      while (j < tk.length && !isOptionStart(tk, j)) {
        j = isPunct(tk[j], "(") || isPunct(tk[j], "[") ? groupEnd(tk, j) + 1 : j + 1;
      }
      returns = normalizeReturns(tk.slice(i + 1, j));
      i = j;
    } else if (isWord(t, "security")) {
      if (isWord(tk[i + 1], "definer")) securityDefiner = true;
      else if (isWord(tk[i + 1], "invoker")) securityDefiner = false;
      i += 2;
    } else if (isWord(t, "as") && tk[i + 1]?.kind === "string") {
      body = tk[i + 1]?.value ?? "";
      i += 2;
    } else if (t && (isWord(t, "return") || (isWord(t, "begin") && isWord(tk[i + 1], "atomic")))) {
      // SQL-standard body; BEGIN ATOMIC bodies are cut at their first semicolon by the splitter.
      body = stmt.text.slice(t.end - stmt.start);
      break;
    } else if (isPunct(t, "(")) {
      i = groupEnd(tk, i) + 1;
    } else {
      i += 1;
    }
  }
  const key = qualifiedKey(q);
  const code = maskSqlComments(body);
  const fn: FunctionState = {
    schema: q.schema,
    name: q.name,
    securityDefiner,
    returns,
    args,
    body: code,
    directCheck: CALLER_CHECKS.some((re) => re.test(code)),
    acl: reg.byKey.get(key)?.acl ?? initialAcl(reg, q.schema),
    location: { file, line: stmt.line },
  };
  reg.byKey.set(key, fn);
}

/** Words a Postgres type can start with; anything else in first place is a parameter name. */
const TYPE_WORD = new Set([
  "anyarray",
  "anyelement",
  "bigint",
  "bigserial",
  "bit",
  "bool",
  "boolean",
  "box",
  "bytea",
  "char",
  "character",
  "cidr",
  "circle",
  "date",
  "decimal",
  "double",
  "float",
  "float4",
  "float8",
  "inet",
  "int",
  "int2",
  "int4",
  "int8",
  "integer",
  "interval",
  "json",
  "jsonb",
  "line",
  "lseg",
  "macaddr",
  "money",
  "name",
  "numeric",
  "oid",
  "path",
  "point",
  "polygon",
  "real",
  "record",
  "regclass",
  "serial",
  "smallint",
  "smallserial",
  "text",
  "time",
  "timestamp",
  "timestamptz",
  "timetz",
  "trigger",
  "tsquery",
  "tsvector",
  "uuid",
  "varbit",
  "varchar",
  "void",
  "xml",
]);

/**
 * Types of the declared parameters, as GRANT and REVOKE need them: `create function f(p_id uuid,
 * count integer default 0)` gives `uuid, integer`. Modes (`in`, `out`, `variadic`), names and
 * defaults are dropped; `out` parameters are not part of the signature. Null when the list holds
 * something this reader does not understand, so the caller can say so instead of guessing.
 */
function argumentTypes(
  stmt: SqlStatement,
  tokens: readonly Token[],
  open: number,
  close: number,
): string | null {
  if (close <= open + 1) return "";
  const parts: string[] = [];
  let depth = 0;
  let start = open + 1;
  const pieces: Array<[number, number]> = [];
  for (let i = open + 1; i < close; i++) {
    const t = tokens[i];
    if (isPunct(t, "(") || isPunct(t, "[")) depth += 1;
    else if (isPunct(t, ")") || isPunct(t, "]")) depth -= 1;
    else if (depth === 0 && isPunct(t, ",")) {
      pieces.push([start, i]);
      start = i + 1;
    }
  }
  pieces.push([start, close]);
  for (const [from, to] of pieces) {
    const words: Token[] = [];
    for (let i = from; i < to; i++) {
      const t = tokens[i];
      if (!t) continue;
      if (isWord(t, "default")) break;
      if (t.kind === "punct" && t.value === "=") break;
      words.push(t);
    }
    if (words.length === 0) return null;
    let k = 0;
    if (isWord(words[k], "in") || isWord(words[k], "out") || isWord(words[k], "inout")) {
      if (isWord(words[k], "out")) continue; // OUT parameters are not part of the signature
      k += 1;
    } else if (isWord(words[k], "variadic")) {
      k += 1;
    }
    // A parameter is `[mode] [name] type`, and only a type name tells the two apart: `p_at
    // timestamp with time zone` has a name, `timestamp with time zone` and `text[]` do not.
    const firstWord = words[k];
    const named =
      firstWord !== undefined &&
      firstWord.kind === "word" &&
      !TYPE_WORD.has(firstWord.value.toLowerCase()) &&
      words.slice(k + 1).some((w) => w.kind === "word");
    const typeStart = named ? k + 1 : k;
    const first = words[typeStart];
    const last = words[words.length - 1];
    if (!first || !last) return null;
    parts.push(
      stmt.text
        .slice(first.start - stmt.start, last.end - stmt.start)
        .replace(/\s+/g, " ")
        .trim()
        .toLowerCase(),
    );
  }
  return parts.join(", ");
}

/** `name[(args)], name2[(args)]` → keys; `next` is the index after the list. */
function readFunctionList(
  tokens: readonly Token[],
  from: number,
): { keys: string[]; next: number } {
  const keys: string[] = [];
  let i = from;
  for (;;) {
    const q = readQualifiedName(tokens, i);
    if (!q) break;
    keys.push(qualifiedKey(q));
    i = q.next;
    if (isPunct(tokens[i], "(")) i = groupEnd(tokens, i) + 1;
    if (!isPunct(tokens[i], ",")) break;
    i += 1;
  }
  return { keys, next: i };
}

/** DROP FUNCTION [IF EXISTS] f(args), g(args) [CASCADE]. */
export function applyDropFunction(reg: FunctionRegistry, stmt: SqlStatement): void {
  const tk = stmt.tokens;
  let i = 2;
  if (isWord(tk[i], "if") && isWord(tk[i + 1], "exists")) i += 2;
  for (const key of readFunctionList(tk, i).keys) reg.byKey.delete(key);
}

/** ALTER FUNCTION f(args) SECURITY DEFINER | RENAME TO g | SET SCHEMA s. */
export function applyAlterFunction(reg: FunctionRegistry, stmt: SqlStatement): void {
  const tk = stmt.tokens;
  const list = readFunctionList(tk, 2);
  const key = list.keys[0];
  const fn = key === undefined ? undefined : reg.byKey.get(key);
  if (!fn || key === undefined) return;
  let i = list.next;
  if (isWord(tk[i], "external")) i += 1;
  if (isWord(tk[i], "security")) {
    if (isWord(tk[i + 1], "definer")) fn.securityDefiner = true;
    else if (isWord(tk[i + 1], "invoker")) fn.securityDefiner = false;
    return;
  }
  let moved: QualifiedName | null = null;
  if (isWord(tk[i], "rename") && isWord(tk[i + 1], "to")) {
    const name = identOf(tk[i + 2]);
    if (name) moved = { schema: fn.schema, name, next: 0 };
  } else if (isWord(tk[i], "set") && isWord(tk[i + 1], "schema")) {
    const schema = identOf(tk[i + 2]);
    if (schema) moved = { schema, name: fn.name, next: 0 };
  }
  if (!moved) return;
  reg.byKey.delete(key);
  fn.schema = moved.schema;
  fn.name = moved.name;
  reg.byKey.set(qualifiedKey(moved), fn);
}

/** Role names after TO/FROM, up to WITH/GRANTED/CASCADE/RESTRICT. */
function readRoles(tokens: readonly Token[], from: number): string[] {
  const roles: string[] = [];
  for (const part of splitTopLevelTokens(tokens.slice(from))) {
    let j = 0;
    if (isWord(part[0], "group")) j = 1;
    const name = identOf(part[j]);
    if (name !== null) roles.push(name.toLowerCase());
  }
  return roles;
}

function applyToAcl(acl: Acl, grant: boolean, roles: readonly string[]): void {
  for (const role of roles) {
    if (role === "public") {
      acl.publicExec = grant;
      acl.explicitPublic = grant;
    } else if (grant) addRole(acl.roles, role);
    else removeRole(acl.roles, role);
  }
}

/** Index of the TO/FROM keyword and of the end of the role list (before WITH/GRANTED/CASCADE/RESTRICT). */
function roleClause(tokens: readonly Token[], from: number, keyword: string): [number, number] {
  let start = -1;
  for (let i = from; i < tokens.length; i += 1) {
    if (isWord(tokens[i], keyword)) {
      start = i + 1;
      break;
    }
  }
  if (start < 0) return [-1, -1];
  let end = start;
  while (
    end < tokens.length &&
    !["with", "granted", "cascade", "restrict"].some((w) => isWord(tokens[end], w))
  ) {
    end += 1;
  }
  return [start, end];
}

/** Privileges up to ON; true when they include EXECUTE (or ALL). */
function grantsExecute(tokens: readonly Token[], from: number): { on: number; execute: boolean } {
  let execute = false;
  for (let i = from; i < tokens.length; i += 1) {
    if (isWord(tokens[i], "on")) return { on: i, execute };
    if (isWord(tokens[i], "execute") || isWord(tokens[i], "all")) execute = true;
  }
  return { on: -1, execute: false };
}

/** GRANT/REVOKE EXECUTE ON FUNCTION ... | ON ALL FUNCTIONS IN SCHEMA ... TO/FROM roles. */
export function applyGrantRevoke(reg: FunctionRegistry, stmt: SqlStatement): void {
  const tk = stmt.tokens;
  const grant = isWord(tk[0], "grant");
  // REVOKE GRANT OPTION FOR only removes the right to re-grant.
  if (!grant && isWord(tk[1], "grant") && isWord(tk[2], "option")) return;
  const priv = grantsExecute(tk, 1);
  if (!priv.execute || priv.on < 0) return;
  let i = priv.on + 1;
  let targets: FunctionState[] = [];
  if (isWord(tk[i], "function") || isWord(tk[i], "routine")) {
    const list = readFunctionList(tk, i + 1);
    targets = list.keys.flatMap((k) => {
      const fn = reg.byKey.get(k);
      return fn ? [fn] : [];
    });
    i = list.next;
  } else if (
    isWord(tk[i], "all") &&
    (isWord(tk[i + 1], "functions") || isWord(tk[i + 1], "routines")) &&
    isWord(tk[i + 2], "in") &&
    isWord(tk[i + 3], "schema")
  ) {
    const schemas: string[] = [];
    i += 4;
    for (;;) {
      const s = identOf(tk[i]);
      if (s === null) break;
      schemas.push(s.toLowerCase());
      i += 1;
      if (!isPunct(tk[i], ",")) break;
      i += 1;
    }
    targets = [...reg.byKey.values()].filter((fn) =>
      schemas.includes((fn.schema ?? "public").toLowerCase()),
    );
  } else {
    return;
  }
  const [start, end] = roleClause(tk, i, grant ? "to" : "from");
  if (start < 0) return;
  const roles = readRoles(tk.slice(0, end), start);
  for (const fn of targets) applyToAcl(fn.acl, grant, roles);
}

/** ALTER DEFAULT PRIVILEGES [FOR ROLE r] [IN SCHEMA s] GRANT|REVOKE ... ON FUNCTIONS TO|FROM roles. */
export function applyDefaultPrivileges(reg: FunctionRegistry, stmt: SqlStatement): void {
  const tk = stmt.tokens;
  let action = -1;
  let schemas: string[] | null = null;
  for (let i = 3; i < tk.length; i += 1) {
    if (isWord(tk[i], "in") && isWord(tk[i + 1], "schema")) {
      schemas = [];
      let j = i + 2;
      for (;;) {
        const s = identOf(tk[j]);
        if (s === null) break;
        schemas.push(s.toLowerCase());
        j += 1;
        if (!isPunct(tk[j], ",")) break;
        j += 1;
      }
    }
    if (isWord(tk[i], "grant") || isWord(tk[i], "revoke")) {
      action = i;
      break;
    }
  }
  if (action < 0) return;
  const grant = isWord(tk[action], "grant");
  if (!grant && isWord(tk[action + 1], "grant") && isWord(tk[action + 2], "option")) return;
  const priv = grantsExecute(tk, action + 1);
  if (!priv.execute || priv.on < 0) return;
  if (!isWord(tk[priv.on + 1], "functions") && !isWord(tk[priv.on + 1], "routines")) return;
  const [start, end] = roleClause(tk, priv.on + 2, grant ? "to" : "from");
  if (start < 0) return;
  const roles = readRoles(tk.slice(0, end), start);
  if (schemas === null) {
    for (const role of roles) {
      if (role === "public") reg.defaultPublic = grant;
      else if (grant) addRole(reg.defaultRoles, role);
      else removeRole(reg.defaultRoles, role);
    }
    return;
  }
  // Per-schema defaults only add to the global ones; a per-schema REVOKE undoes a per-schema GRANT.
  if (!schemas.includes("public")) return;
  for (const role of roles) {
    if (role === "public") reg.publicSchemaPublic = grant;
    else if (grant) addRole(reg.publicSchemaRoles, role);
    else removeRole(reg.publicSchemaRoles, role);
  }
}

/**
 * Calls in SQL text: `f(`, `public.f(`, `"private"."f" (`. Matches start at identifier boundaries and
 * names are bounded (Postgres truncates at 63 bytes), so hostile input cannot make this quadratic.
 */
const CALL =
  /(?<![A-Za-z0-9_$])(?:"?([A-Za-z_][A-Za-z0-9_$]{0,62})"?\s*\.\s*)?"?([A-Za-z_][A-Za-z0-9_$]{0,62})"?\s*\(/g;

/** Functions of the registry that `f` calls. Unqualified calls resolve to `public` first, then by name. */
function callees(
  reg: FunctionRegistry,
  f: FunctionState,
  byName: Map<string, FunctionState>,
): Set<FunctionState> {
  const out = new Set<FunctionState>();
  for (const m of f.body.matchAll(CALL)) {
    const name = m[2];
    if (!name) continue;
    const g =
      reg.byKey.get(qualifiedKey({ schema: m[1] ?? null, name })) ??
      (m[1] === undefined ? byName.get(name.toLowerCase()) : undefined);
    if (g && g !== f) out.add(g);
  }
  return out;
}

function effectiveRoles(acl: Acl): string[] {
  const out: string[] = [];
  if (acl.publicExec || acl.roles.includes("anon")) out.push("anon");
  if (acl.publicExec || acl.roles.includes("authenticated")) out.push("authenticated");
  for (const r of acl.roles) if (r !== "anon" && r !== "authenticated") addRole(out, r);
  if (acl.explicitPublic) addRole(out, "public");
  return out;
}

/**
 * Final function list. `checksCaller` propagates through calls: a definer function that filters by
 * `current_tenant_id()` checks the caller when `current_tenant_id()` itself reads `auth.uid()`.
 */
export function finishFunctions(reg: FunctionRegistry): SqlFunctionInfo[] {
  const fns = [...reg.byKey.values()];
  const byName = new Map<string, FunctionState>();
  for (const f of fns) {
    if (!isPublicSchema(f.schema) && !byName.has(f.name.toLowerCase())) {
      byName.set(f.name.toLowerCase(), f);
    }
  }
  const callers = new Map<FunctionState, FunctionState[]>();
  for (const f of fns) {
    for (const g of callees(reg, f, byName)) callers.set(g, [...(callers.get(g) ?? []), f]);
  }
  const checks = new Set(fns.filter((f) => f.directCheck));
  const queue = [...checks];
  for (let g = queue.pop(); g !== undefined; g = queue.pop()) {
    for (const f of callers.get(g) ?? []) {
      if (checks.has(f)) continue;
      checks.add(f);
      queue.push(f);
    }
  }
  return fns.map((f) => {
    const info: SqlFunctionInfo = {
      name: qualifiedKey(f),
      securityDefiner: f.securityDefiner,
      checksCaller: checks.has(f),
      grantedTo: effectiveRoles(f.acl),
      location: f.location,
    };
    if (f.returns !== null) info.returns = f.returns;
    if (f.args !== null) info.args = f.args;
    return info;
  });
}
