import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import ts from "typescript";
import {
  boundNames,
  type ChainSegment,
  type ClassInfo,
  collect,
  enclosingStatement,
  exportedFunctions,
  type FunctionLike,
  flattenChain,
  isChainTail,
  isFunctionLikeNode,
  lineOf,
  ownReturns,
  parseIgnoreDirectives,
  parseSource,
  stringLiteralValue,
  unwrap,
  walk,
} from "./ast.js";
import { isCredentialColumn, isSessionProviderImport, secretChecksIn } from "./auth-evidence.js";
import { discoverFiles } from "./discover.js";
import {
  callResultChecked,
  compareOrder,
  missingRowExit,
  outerOf,
  rowComparisons,
} from "./guards.js";
import type {
  AuthCheck,
  AuthHelper,
  ClientFactory,
  ClientKind,
  EntryKind,
  FileRef,
  HttpMethod,
  IgnoreDirective,
  InputKind,
  InputSource,
  MetadataAccess,
  ProjectModel,
  QueryFilter,
  QueryGuard,
  QueryOperation,
  QueryPayload,
  RlsTable,
  RoleCheck,
  RouteHandler,
  SecretExposure,
  SupabaseQuery,
} from "./model.js";
import {
  isClientComponentFile,
  isServerActionFile,
  pageFromFile,
  pageHandlerIn,
  routeFromFile,
  routeHandlersIn,
} from "./nextjs.js";
import {
  clientCreatingOperand,
  DRIZZLE_QUERY_API,
  DRIZZLE_WRITE_OPS,
  drizzleFilters,
  isDrizzleCall,
  isPrismaNew,
  type OrmFilter,
  objectProperty,
  PRISMA_OPS,
  parsePrismaSchema,
  prismaWhereFilters,
} from "./orm.js";
import { Resolver } from "./resolve.js";
import { appliedSqlFiles, parseSqlForRls, sqlSchemaFor } from "./rls.js";
import { roleGatesIn, sessionNamesIn } from "./role-gates.js";
import {
  bucketName,
  CallerScope,
  STORAGE_OPS,
  type StorageCall,
  storageAccessOf,
  storageBindingsIn,
  storageCallOf,
} from "./storage.js";
import {
  analyzeModule,
  classifyCreateClientCall,
  isCreateClientCall,
  type ModuleFacts,
} from "./supabase.js";
import { isWholeInput, type WholeContext, wholeParamNames } from "./whole-input.js";

const FILTER_METHODS = new Set([
  "eq",
  "neq",
  "gt",
  "gte",
  "lt",
  "lte",
  "like",
  "ilike",
  "is",
  "in",
  "contains",
  "containedBy",
  "match",
  "filter",
  "not",
  "or",
  "textSearch",
]);
const WRITE_OPERATIONS = new Set<QueryOperation>(["insert", "update", "upsert"]);
const OPERATIONS = new Set<QueryOperation>(["select", "insert", "update", "delete", "upsert"]);
const PUBLIC_SECRET_ENV = /^NEXT_PUBLIC_[A-Z0-9_]*(?:SERVICE_ROLE|SECRET)[A-Z0-9_]*$/;
/** How many helper calls deep a handler is followed: handler -> helper -> helper -> helper. */
const MAX_DEPTH = 3;
/** Wrappers that authenticate the caller before invoking the wrapped handler (Makerkit, next-safe-action, custom). */
const WRAPPER_AUTH = /enhance(Action|RouteHandler)|auth|protected|session|guard|require|withUser/i;
const REQUEST_NAME = /^(req|request)$/;

interface ClientBinding {
  kind: ClientKind;
  name: string;
  location: FileRef;
}

/** A service object built from a class: `const api = createAccountsApi(client)`. */
interface InstanceBinding {
  cls: ClassInfo;
  facts: ModuleFacts;
  ctorArgs: ArgBinding[];
}

/** What a call argument carries into the callee. */
interface ArgBinding {
  client: ClientBinding | null;
  instance: InstanceBinding | null;
  tainted: boolean;
  /** The argument is an entire request input object (see whole-input.ts), not just derived from one. */
  whole: boolean;
  isRequest: boolean;
}

const NO_ARG: ArgBinding = {
  client: null,
  instance: null,
  tainted: false,
  whole: false,
  isRequest: false,
};

type Sym =
  | { kind: "factory"; factory: ClientFactory }
  | { kind: "auth"; helper: AuthHelper; fn?: FunctionLike; facts?: ModuleFacts }
  | { kind: "function"; name: string; fn: FunctionLike; facts: ModuleFacts }
  | { kind: "class"; cls: ClassInfo; facts: ModuleFacts }
  | { kind: "var"; name: string; init: ts.Expression; facts: ModuleFacts }
  | { kind: "namespace"; facts: ModuleFacts }
  | { kind: "table"; table: string };

interface Project {
  sources: Map<string, ts.SourceFile>;
  registry: Map<string, ModuleFacts>;
  resolver: Resolver;
  scopes: Map<string, Map<string, Sym>>;
  factoryOfFn: Map<string, ClientBinding | null>;
  varBindings: Map<string, ArgBinding>;
  /** Drizzle schema export name -> table, across the whole project (for `db.query.<export>`). */
  drizzleTablesByExport: Map<string, string>;
  /** Prisma model accessor (`prisma.invoice`) -> table. */
  prismaModels: Map<string, string>;
  /** Memo of returnTaint by helper and bindings; null marks a helper being analysed (recursion). */
  returnTaints: Map<string, ReturnTaint | null>;
  /** Memo of returnIdentity: `false` when the helper returns something other than an identity. */
  returnIdentities: Map<string, { who: string | null } | false>;
  /** Tables from the migrations, for foreign keys between a guard read and the row it guards. */
  tables: ReadonlyMap<string, RlsTable>;
  warnings: string[];
}

/** One function body being analysed on behalf of a handler, with what the caller bound into it. */
interface Frame {
  rel: string;
  sf: ts.SourceFile;
  facts: ModuleFacts;
  fn: FunctionLike;
  depth: number;
  via: string[];
  /** Identifiers holding user-controlled data. */
  inputNames: Set<string>;
  /** Identifiers holding an entire request input object (a subset of inputNames). */
  wholeNames: Set<string>;
  /** Objects only some of whose properties are user input: name -> those property names. */
  partialInputs: Map<string, Set<string>>;
  /** Identifiers holding the incoming Request object. */
  reqNames: Set<string>;
  clients: Map<string, ClientBinding>;
  instances: Map<string, InstanceBinding>;
  cls: ClassInfo | null;
  thisProps: Map<string, ArgBinding>;
  /** Names this frame's local values in value keys (`h` for the entry point itself). */
  key: string;
  /** Parameter (or `param.prop`) -> the caller's value key for the argument bound to it. */
  aliases: Map<string, string>;
  /** Source positions of the calls from the entry point down to this frame. */
  pathPos: number[];
  /** A `return` in this frame ends the entry point: every call site up to it checks the result. */
  exitPropagates: boolean;
  /**
   * Identifiers holding the caller's identity or a row it selected: the session user (null), the
   * account a request credential looked up or a row filtered by an identity (its table), a part of
   * such a row (""). See identityOf.
   */
  identities: Map<string, string | null>;
}

/** A query as a possible guard: the value keys of its filters, its place in the call order, its stop. */
interface GuardableRead {
  query: SupabaseQuery;
  keys: Array<string | null>;
  order: number[];
  /** A missing row stops the entry point. */
  exits: boolean;
  /** Comparisons of the row in code that stop the entry point (`existing.user_id !== user.id`). */
  checks: QueryFilter[];
}

interface Acc {
  inputs: InputSource[];
  authChecks: AuthCheck[];
  roleChecks: RoleCheck[];
  queries: SupabaseQuery[];
  metadataAccesses: MetadataAccess[];
  visited: Set<string>;
  reads: GuardableRead[];
}

export interface ParseOptions {
  /** Extra directories to scan for migration SQL, absolute or relative to the project root. */
  sqlDirs?: readonly string[];
  /** Glob patterns (relative to root) to leave out of the scan, e.g. intentionally vulnerable fixtures. */
  ignore?: readonly string[];
}

// ---------------------------------------------------------------------------------------------
// Module scope: what each identifier in a module refers to, across imports and re-exports.

function ownFunctionSym(facts: ModuleFacts, name: string, fn: FunctionLike): Sym {
  const factory = facts.clientFactories.find((c) => c.name === name);
  if (factory) return { kind: "factory", factory };
  const helper = facts.authHelpers.find((a) => a.name === name);
  if (helper) return { kind: "auth", helper, fn, facts };
  return { kind: "function", name, fn, facts };
}

function exportedSym(p: Project, tf: ModuleFacts, name: string, depth: number): Sym | null {
  if (depth > 5) return null;
  const f = tf.functions.get(name);
  if (f?.exported) return ownFunctionSym(tf, name, f.fn);
  const c = tf.classes.get(name);
  if (c?.exported) return { kind: "class", cls: c, facts: tf };
  const v = tf.moduleVars.get(name);
  if (v?.exported) return { kind: "var", name, init: v.init, facts: tf };
  const dt = tf.drizzleTables.get(name);
  if (dt !== undefined) return { kind: "table", table: dt };
  const av = tf.authVars.get(name);
  if (av?.exported) return { kind: "auth", helper: av.helper };
  if (name === "default" && tf.defaultExport) {
    const local = tf.defaultExport;
    const lf = tf.functions.get(local);
    if (lf) return ownFunctionSym(tf, local, lf.fn);
    const lc = tf.classes.get(local);
    if (lc) return { kind: "class", cls: lc, facts: tf };
    const lv = tf.moduleVars.get(local);
    if (lv) return { kind: "var", name: local, init: lv.init, facts: tf };
  }
  for (const r of tf.reexports) {
    const target = p.resolver.resolve(r.spec, tf.file);
    const t = target ? p.registry.get(target) : undefined;
    if (!t) continue;
    if (r.star) {
      const s = exportedSym(p, t, name, depth + 1);
      if (s) return s;
    } else if (r.alias === name) {
      const s = exportedSym(p, t, r.name, depth + 1);
      if (s) return s;
    }
  }
  return null;
}

function scopeOf(p: Project, facts: ModuleFacts): Map<string, Sym> {
  const cached = p.scopes.get(facts.file);
  if (cached) return cached;
  const scope = new Map<string, Sym>();
  p.scopes.set(facts.file, scope);
  for (const [name, f] of facts.functions) scope.set(name, ownFunctionSym(facts, name, f.fn));
  for (const [name, c] of facts.classes) scope.set(name, { kind: "class", cls: c, facts });
  for (const [name, v] of facts.moduleVars) {
    scope.set(name, { kind: "var", name, init: v.init, facts });
  }
  for (const [name, table] of facts.drizzleTables) scope.set(name, { kind: "table", table });
  for (const [name, v] of facts.authVars) scope.set(name, { kind: "auth", helper: v.helper });
  for (const [local, ref] of facts.imports) {
    const target = p.resolver.resolve(ref.spec, facts.file);
    const tf = target ? p.registry.get(target) : undefined;
    if (tf) {
      if (ref.imported === "*") scope.set(local, { kind: "namespace", facts: tf });
      else {
        const sym = exportedSym(p, tf, ref.imported, 0);
        if (sym) scope.set(local, sym);
      }
      continue;
    }
    if (isSessionProviderImport(ref.spec, ref.imported)) {
      // `getServerSession` (next-auth), `auth()`/`currentUser()` (Clerk) return the caller's session.
      scope.set(local, {
        kind: "auth",
        helper: {
          name: local,
          location: { file: facts.file, line: 1 },
          evidence: `${ref.imported} from ${ref.spec}`,
        },
      });
      continue;
    }
    if (!/^[.~]|^@\//.test(ref.spec)) continue;
    // Unresolvable local import (unusual alias): fall back to a unique helper of that name.
    for (const f of p.registry.values()) {
      const fn = f.functions.get(ref.imported);
      if (!fn?.exported) continue;
      const sym = ownFunctionSym(f, ref.imported, fn.fn);
      if (sym.kind === "factory" || sym.kind === "auth") {
        scope.set(local, sym);
        p.warnings.push(
          `unresolved import "${ref.spec}" in ${facts.file}; matched "${ref.imported}" by name`,
        );
        break;
      }
    }
  }
  return scope;
}

function symOfCallee(p: Project, callee: ts.Expression, scope: Map<string, Sym>): Sym | undefined {
  if (ts.isIdentifier(callee)) return scope.get(callee.text);
  if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)) {
    const ns = scope.get(callee.expression.text);
    if (ns?.kind === "namespace") return exportedSym(p, ns.facts, callee.name.text, 0) ?? undefined;
  }
  return undefined;
}

/** Expressions a function can return (arrow expression bodies and `return` statements). */
function returnedExpressions(fn: FunctionLike): ts.Expression[] {
  if (!fn.body) return [];
  if (!ts.isBlock(fn.body)) return [fn.body];
  return collect(fn.body, ts.isReturnStatement)
    .map((r) => r.expression)
    .filter((e): e is ts.Expression => e !== undefined);
}

/** A function that returns another factory's client (`export function getDb() { return getServerClient(); }`). */
function factoryOfFunction(
  p: Project,
  sym: Extract<Sym, { kind: "function" }>,
  depth: number,
): ClientBinding | null {
  const key = `${sym.facts.file}#${sym.name}`;
  if (p.factoryOfFn.has(key)) return p.factoryOfFn.get(key) ?? null;
  p.factoryOfFn.set(key, null);
  const sf = p.sources.get(sym.facts.file);
  if (!sf || depth > 2) return null;
  const scope = scopeOf(p, sym.facts);
  let found: ClientBinding | null = null;
  for (const ret of returnedExpressions(sym.fn)) {
    const u = unwrap(ret);
    if (!ts.isCallExpression(u)) continue;
    found = classifyCall(p, u, sf, scope, null, depth + 1);
    if (found) break;
  }
  p.factoryOfFn.set(key, found);
  return found;
}

/** Client produced by a call: a factory (local or imported), a wrapper around one, or createClient itself. */
function classifyCall(
  p: Project,
  call: ts.CallExpression,
  sf: ts.SourceFile,
  scope: Map<string, Sym>,
  frame: Frame | null,
  depth: number,
): ClientBinding | null {
  const extended = prismaExtensionBase(p, call, sf, scope, frame, depth);
  if (extended) return extended;
  const sym = symOfCallee(p, call.expression, scope);
  if (sym?.kind === "factory") {
    return { kind: sym.factory.kind, name: sym.factory.name, location: sym.factory.location };
  }
  if (sym?.kind === "function") {
    const b = factoryOfFunction(p, sym, depth);
    if (b) return b;
  }
  if (isDrizzleCall(call)) {
    return {
      kind: "direct_db",
      name: "drizzle",
      location: { file: sf.fileName, line: lineOf(sf, call) },
    };
  }
  if (isCreateClientCall(call, sf)) {
    const c = classifyCreateClientCall(call, sf);
    return {
      kind: c.kind,
      name: call.expression.getText(sf),
      location: { file: sf.fileName, line: lineOf(sf, call) },
    };
  }
  return null;
}

/**
 * A Prisma client extension is still the same direct connection: `prisma.$extends(ext)`,
 * `new PrismaClient().$extends(a).$extends(b)` (expense.fyi exports only the extended client).
 */
function prismaExtensionBase(
  p: Project,
  call: ts.CallExpression,
  sf: ts.SourceFile,
  scope: Map<string, Sym>,
  frame: Frame | null,
  depth: number,
): ClientBinding | null {
  const callee = call.expression;
  if (!ts.isPropertyAccessExpression(callee) || callee.name.text !== "$extends") return null;
  if (depth > 5) return null;
  const base = unwrap(callee.expression);
  if (isPrismaNew(base)) {
    return {
      kind: "direct_db",
      name: "PrismaClient",
      location: { file: sf.fileName, line: lineOf(sf, call) },
    };
  }
  if (ts.isCallExpression(base)) return classifyCall(p, base, sf, scope, frame, depth + 1);
  if (!ts.isIdentifier(base)) return null;
  const bound = frame?.clients.get(base.text);
  if (bound) return bound;
  const sym = scope.get(base.text);
  return sym?.kind === "var" ? varBinding(p, sym).client : null;
}

/** `createAccountsApi(client)` -> the class instance it returns, with constructor arguments bound from the call site. */
function instanceOfCall(
  p: Project,
  call: ts.CallExpression,
  frame: Frame | null,
  scope: Map<string, Sym>,
): InstanceBinding | null {
  const sym = symOfCallee(p, call.expression, scope);
  if (sym?.kind !== "function") return null;
  const fscope = scopeOf(p, sym.facts);
  const params = sym.fn.parameters.map((pp) => (ts.isIdentifier(pp.name) ? pp.name.text : null));
  for (const ret of returnedExpressions(sym.fn)) {
    const u = unwrap(ret);
    if (!ts.isNewExpression(u) || !ts.isIdentifier(u.expression)) continue;
    const cs = fscope.get(u.expression.text);
    if (cs?.kind !== "class") continue;
    const ctorArgs = (u.arguments ?? []).map((a) => {
      const ua = unwrap(a);
      if (ts.isIdentifier(ua)) {
        const j = params.indexOf(ua.text);
        if (j >= 0 && frame) return argBinding(p, call.arguments[j], frame);
      }
      return NO_ARG;
    });
    return { cls: cs.cls, facts: cs.facts, ctorArgs };
  }
  return null;
}

/** Module-level `const supabase = createClient(...)` / `const api = new Api(...)`, classified once. */
function varBinding(p: Project, sym: Extract<Sym, { kind: "var" }>): ArgBinding {
  const key = `${sym.facts.file}#${sym.name}`;
  const cached = p.varBindings.get(key);
  if (cached) return cached;
  p.varBindings.set(key, NO_ARG);
  const sf = p.sources.get(sym.facts.file);
  if (!sf) return NO_ARG;
  const scope = scopeOf(p, sym.facts);
  const init = clientCreatingOperand(sym.init);
  let out: ArgBinding = NO_ARG;
  if (isPrismaNew(init)) {
    out = {
      client: {
        kind: "direct_db",
        name: sym.name,
        location: { file: sym.facts.file, line: lineOf(sf, init) },
      },
      instance: null,
      tainted: false,
      whole: false,
      isRequest: false,
    };
  } else if (ts.isCallExpression(init)) {
    const found = classifyCall(p, init, sf, scope, null, 0);
    // Evidence names the module-level binding (`supabaseAdmin`), not the factory it wraps.
    const client = found
      ? {
          kind: found.kind,
          name: sym.name,
          location: { file: sym.facts.file, line: lineOf(sf, init) },
        }
      : null;
    const instance = client ? null : instanceOfCall(p, init, null, scope);
    out = { client, instance, tainted: false, whole: false, isRequest: false };
  } else if (ts.isNewExpression(init) && ts.isIdentifier(init.expression)) {
    const cs = scope.get(init.expression.text);
    if (cs?.kind === "class") {
      out = {
        client: null,
        instance: { cls: cs.cls, facts: cs.facts, ctorArgs: [] },
        tainted: false,
        whole: false,
        isRequest: false,
      };
    }
  }
  p.varBindings.set(key, out);
  return out;
}

function isQueryChain(call: ts.CallExpression): boolean {
  return flattenChain(call).segments.some((s) => s.name === "from" || s.name === "rpc");
}

function derivedIn(frame: Frame, e: ts.Node): boolean {
  if (usesInput(frame, e)) return true;
  // In the handler itself, `params.x` / `body.x` are user input even before we saw the binding.
  return frame.depth === 0 && /^(params|body|query|searchParams)\b/.test(e.getText(frame.sf));
}

/**
 * Variables read by `e` that hold user input. A partially tainted object (`input` bound to
 * `{ accountId, contactId: body.contact_id }`) taints `input.contactId` and the bare `input`, but not
 * `input.accountId`, which came from the session.
 */
function usesInput(frame: Frame, e: ts.Node): boolean {
  let hit = false;
  walk(e, (n) => {
    if (hit) return false;
    if (ts.isCallExpression(n) && handsOverRequest(frame, n)) {
      hit = true;
      return false;
    }
    if (!ts.isIdentifier(n)) return undefined;
    const parent = n.parent;
    if (parent && ts.isPropertyAccessExpression(parent) && parent.name === n) return undefined;
    if (parent && ts.isPropertyAssignment(parent) && parent.name === n) return undefined;
    const member = parent && ts.isPropertyAccessExpression(parent) && parent.expression === n;
    if (frame.inputNames.has(n.text)) hit = true;
    else if (member && frame.reqNames.has(n.text) && REQUEST_MEMBER.test(parent.name.text)) {
      hit = true;
    }
    const partial = frame.partialInputs.get(n.text);
    if (partial && (!member || partial.has(parent.name.text))) hit = true;
    return undefined;
  });
  return hit;
}

/**
 * A read of something the caller sends, at any depth: `cookies()` and `headers()` from next/headers
 * (awaited or not), `cookieStore.get("x")?.value`, `req.cookies.get(...)`. Deliberately narrow: it
 * must be a read, not a write (`cookieStore.set`) and not the store itself being passed to a client.
 */
const CALLER_READ =
  /\b(?:await\s+)?cookies\(\)\s*(?:\.|$)|cookieStore\s*\.\s*get\s*\(|\bcookies\s*\.\s*get\s*\(|\b(?:await\s+)?headers\(\)\s*\.\s*get\s*\(/;

/** What the caller controls on a Request: body readers, headers, cookies, URL (not `req.auth`, a session). */
const REQUEST_MEMBER =
  /^(json|formData|text|arrayBuffer|blob|body|headers|cookies|url|nextUrl|query|params|ip|geo)$/;
/** Helpers handed the request that build a client, not data. */
const REQUEST_CLIENT_CALLEE = /client|supabase|prisma|drizzle/i;

/** `readJsonWithLimit(req)` nested in an argument: a helper handed the request returns its input. */
function handsOverRequest(frame: Frame, call: ts.CallExpression): boolean {
  if (frame.reqNames.size === 0) return false;
  const callee = calleePath(call.expression);
  if (IDENTITY_CALLEE.test(callee) || REQUEST_CLIENT_CALLEE.test(callee)) return false;
  return call.arguments.some((a) => {
    const u = unwrap(a);
    return ts.isIdentifier(u) && frame.reqNames.has(u.text);
  });
}

function propertyKeyOf(name: ts.PropertyName | ts.BindingName | undefined): string | null {
  if (name && (ts.isIdentifier(name) || ts.isStringLiteral(name))) return name.text;
  return null;
}

/** Property names of an object literal whose values carry user input, or null when a spread does. */
function taintedProperties(frame: Frame, lit: ts.ObjectLiteralExpression): Set<string> | null {
  const out = new Set<string>();
  for (const pr of lit.properties) {
    if (ts.isSpreadAssignment(pr)) {
      if (derivedIn(frame, pr.expression)) return null;
      continue;
    }
    const key = propertyKeyOf(pr.name);
    if (key === null) continue;
    if (ts.isPropertyAssignment(pr) && derivedIn(frame, pr.initializer)) out.add(key);
    else if (ts.isShorthandPropertyAssignment(pr) && derivedIn(frame, pr.name)) out.add(key);
  }
  return out;
}

/**
 * Binds user input into a callee parameter. An object literal argument keeps its per-property taint:
 * `run({ accountId, contactId: body.contact_id })` taints `input.contactId` (or the destructured
 * `contactId`), never the session-derived `accountId`.
 */
function bindParamTaint(
  child: Frame,
  param: ts.BindingName,
  arg: ts.Expression | undefined,
  frame: Frame,
): void {
  const u = arg ? unwrap(arg) : undefined;
  let props: Set<string> | null = null;
  if (u && ts.isObjectLiteralExpression(u)) props = taintedProperties(frame, u);
  else if (u && ts.isIdentifier(u) && !frame.inputNames.has(u.text)) {
    props = frame.partialInputs.get(u.text) ?? null;
  }
  if (props === null) {
    for (const nm of boundNames(param)) child.inputNames.add(nm);
    return;
  }
  if (ts.isIdentifier(param)) {
    child.partialInputs.set(param.text, new Set(props));
    return;
  }
  bindPatternFrom(child, param, props);
}

/** `const { accountId, contactId } = input` (or a destructured parameter) from a partially tainted object. */
function bindPatternFrom(child: Frame, pattern: ts.BindingName, props: ReadonlySet<string>): void {
  if (!ts.isObjectBindingPattern(pattern)) {
    if (props.size > 0) for (const nm of boundNames(pattern)) child.inputNames.add(nm);
    return;
  }
  for (const el of pattern.elements) {
    const key = propertyKeyOf(el.propertyName ?? el.name);
    if (el.dotDotDotToken ? props.size > 0 : key !== null && props.has(key)) {
      for (const nm of boundNames(el.name)) child.inputNames.add(nm);
    }
  }
}

/** `req.json()` / `req.formData()` / `req.text()` on the incoming request, at any depth. */
function isRequestBodyCall(frame: Frame, call: ts.CallExpression): boolean {
  const callee = call.expression;
  if (!ts.isPropertyAccessExpression(callee) || !/^(json|formData|text)$/.test(callee.name.text)) {
    return false;
  }
  const recv = unwrap(callee.expression);
  if (!ts.isIdentifier(recv)) return false;
  if (frame.reqNames.has(recv.text)) return true;
  return frame.depth === 0 && frame.reqNames.size === 0 && REQUEST_NAME.test(recv.text);
}

function wholeContext(p: Project, frame: Frame): WholeContext {
  return {
    wholeName: (n) => frame.wholeNames.has(n),
    requestBody: (c) => isRequestBodyCall(frame, c),
    requestName: (n) => frame.reqNames.has(n),
    strippingSchema: (e) => isStrippingSchema(p, frame, e),
  };
}

/** An object schema that drops unknown keys: `z.object({...})`, with or without `.strict()`. */
const OBJECT_SCHEMA = /\b(?:z|zod|v|valibot|yup)\s*\.\s*object\s*\(/;
/** Modifiers that keep whatever the caller sent, which makes the parse no allow-list at all. */
const SCHEMA_KEEPS_UNKNOWN = /\.\s*(?:passthrough|catchall|nonstrict|unknown)\s*\(/;

/**
 * Is this expression a schema of this project that keeps only the fields it declares? Resolved
 * through the module scope, so an imported `levelSchema` is judged by its own declaration; an
 * unresolvable name is not a schema as far as we know.
 */
function isStrippingSchema(p: Project, frame: Frame, e: ts.Expression): boolean {
  const u = unwrap(e);
  if (ts.isCallExpression(u) || ts.isPropertyAccessExpression(u)) {
    const text = u.getText();
    return OBJECT_SCHEMA.test(text) && !SCHEMA_KEEPS_UNKNOWN.test(text);
  }
  if (!ts.isIdentifier(u)) return false;
  const sym = scopeOf(p, frame.facts).get(u.text);
  if (sym?.kind !== "var") return false;
  const text = sym.init.getText();
  return OBJECT_SCHEMA.test(text) && !SCHEMA_KEEPS_UNKNOWN.test(text);
}

/**
 * A method called on user-controlled data returns user-controlled data: `formData.get("id")`,
 * `url.searchParams.get("id")`, `ids.map(...)`, and anything read off the incoming request
 * (`req.headers.get(...)`, `req.json()`).
 */
function receiverTainted(frame: Frame, call: ts.CallExpression): boolean {
  const callee = call.expression;
  if (!ts.isPropertyAccessExpression(callee) && !ts.isElementAccessExpression(callee)) return false;
  // The callee, not only its receiver: `req.json` reads the body, `req.auth` would be the session.
  return derivedIn(frame, callee);
}

function argBinding(p: Project, arg: ts.Expression | undefined, frame: Frame): ArgBinding {
  if (!arg) return NO_ARG;
  const u = unwrap(arg);
  const scope = scopeOf(p, frame.facts);
  let client: ClientBinding | null = null;
  let instance: InstanceBinding | null = null;
  let isRequest = false;
  if (ts.isIdentifier(u)) {
    client = frame.clients.get(u.text) ?? null;
    instance = frame.instances.get(u.text) ?? null;
    isRequest = frame.reqNames.has(u.text);
    if (!client && !instance) {
      const sym = scope.get(u.text);
      if (sym?.kind === "var") {
        const vb = varBinding(p, sym);
        client = vb.client;
        instance = vb.instance;
      }
    }
  } else if (ts.isPropertyAccessExpression(u) && u.expression.kind === ts.SyntaxKind.ThisKeyword) {
    const tp = frame.thisProps.get(u.name.text);
    if (tp) {
      client = tp.client;
      instance = tp.instance;
      isRequest = tp.isRequest;
    }
  } else if (ts.isCallExpression(u)) {
    client = classifyCall(p, u, frame.sf, scope, frame, 0);
    if (!client) instance = instanceOfCall(p, u, frame, scope);
  } else if (isPrismaNew(u)) {
    client = {
      kind: "direct_db",
      name: "PrismaClient",
      location: { file: frame.rel, line: lineOf(frame.sf, u) },
    };
  } else if (ts.isNewExpression(u) && ts.isIdentifier(u.expression)) {
    const cs = scope.get(u.expression.text);
    if (cs?.kind === "class") {
      instance = {
        cls: cs.cls,
        facts: cs.facts,
        ctorArgs: (u.arguments ?? []).map((a) => argBinding(p, a, frame)),
      };
    }
  }
  return {
    client,
    instance,
    tainted: derivedIn(frame, arg),
    whole: isWholeInput(arg, wholeContext(p, frame)),
    isRequest,
  };
}

interface CallTarget {
  fn: FunctionLike;
  facts: ModuleFacts;
  name: string;
  cls: ClassInfo | null;
  thisProps: Map<string, ArgBinding>;
}

function methodTarget(inst: InstanceBinding, method: string): CallTarget | null {
  const m = inst.cls.methods.get(method);
  if (!m) return null;
  const thisProps = new Map<string, ArgBinding>();
  for (const [prop, idx] of inst.cls.propFromParam)
    thisProps.set(prop, inst.ctorArgs[idx] ?? NO_ARG);
  return { fn: m, facts: inst.facts, name: `${inst.cls.name}.${method}`, cls: inst.cls, thisProps };
}

function callTarget(
  p: Project,
  call: ts.CallExpression,
  frame: Frame,
  scope: Map<string, Sym>,
): CallTarget | null {
  const callee = call.expression;
  if (ts.isIdentifier(callee)) {
    const sym = scope.get(callee.text);
    if (sym?.kind === "function") {
      return { fn: sym.fn, facts: sym.facts, name: sym.name, cls: null, thisProps: new Map() };
    }
    // An auth helper is still a function: its own queries (an ownership read, a profile lookup)
    // belong to the entry point that calls it.
    if (sym?.kind === "auth" && sym.fn && sym.facts) {
      return {
        fn: sym.fn,
        facts: sym.facts,
        name: sym.helper.name,
        cls: null,
        thisProps: new Map(),
      };
    }
    return null;
  }
  if (!ts.isPropertyAccessExpression(callee)) return null;
  const obj = callee.expression;
  const method = callee.name.text;
  if (ts.isIdentifier(obj)) {
    const inst = frame.instances.get(obj.text);
    if (inst) return methodTarget(inst, method);
    const sym = scope.get(obj.text);
    if (sym?.kind === "namespace") {
      const s = exportedSym(p, sym.facts, method, 0);
      if (s?.kind === "function") {
        return { fn: s.fn, facts: s.facts, name: s.name, cls: null, thisProps: new Map() };
      }
      if (s?.kind === "auth" && s.fn && s.facts) {
        return { fn: s.fn, facts: s.facts, name: s.helper.name, cls: null, thisProps: new Map() };
      }
    } else if (sym?.kind === "var") {
      const vb = varBinding(p, sym);
      if (vb.instance) return methodTarget(vb.instance, method);
    }
    return null;
  }
  if (obj.kind === ts.SyntaxKind.ThisKeyword && frame.cls) {
    const m = frame.cls.methods.get(method);
    if (!m) return null;
    return {
      fn: m,
      facts: frame.facts,
      name: `${frame.cls.name}.${method}`,
      cls: frame.cls,
      thisProps: frame.thisProps,
    };
  }
  if (ts.isPropertyAccessExpression(obj) && obj.expression.kind === ts.SyntaxKind.ThisKeyword) {
    const tp = frame.thisProps.get(obj.name.text);
    if (tp?.instance) return methodTarget(tp.instance, method);
  }
  return null;
}

// ---------------------------------------------------------------------------------------------
// Frame analysis.

/**
 * Declarations of one function in source order: request inputs (handler only), client bindings,
 * service instances and taint propagation into locals. Runs for the entry point and for every
 * helper frame, and again on a callee when a caller needs to know what its result carries
 * (see returnTaint).
 */
function bindDeclarations(p: Project, frame: Frame, acc: Acc): void {
  const { rel, sf, fn } = frame;
  const scope = scopeOf(p, frame.facts);
  const loc = (n: ts.Node): FileRef => ({ file: rel, line: lineOf(sf, n) });
  const body: ts.Node = fn.body ?? fn;

  // Module-level clients and service instances visible from this function.
  for (const [name, sym] of scope) {
    if (sym.kind !== "var" || frame.clients.has(name) || frame.instances.has(name)) continue;
    const vb = varBinding(p, sym);
    if (vb.client) frame.clients.set(name, vb.client);
    if (vb.instance) frame.instances.set(name, vb.instance);
  }

  const addInput = (kind: InputKind, name: string, n: ts.Node, bind: boolean): void => {
    if (!acc.inputs.some((i) => i.kind === kind && i.name === name)) {
      acc.inputs.push({ kind, name, location: loc(n) });
    }
    if (bind) frame.inputNames.add(name);
  };
  const isRequestCall = (text: string): boolean => {
    if (!/\.(json|formData|text)\(\)$/.test(text)) return false;
    for (const r of frame.reqNames) if (text.startsWith(`${r}.`)) return true;
    return frame.reqNames.size === 0 && /^(req|request)\./.test(text);
  };
  /** Binds names to user input; `whole` when the value is the caller's entire object. */
  const bindInput = (names: string[], whole: boolean): void => {
    for (const nm of names) {
      frame.inputNames.add(nm);
      if (whole) frame.wholeNames.add(nm);
    }
  };
  const handlerInput = (kind: InputKind, names: string[], decl: ts.VariableDeclaration): void => {
    for (const nm of names) addInput(kind, nm, decl, true);
    bindInput(names, true);
  };

  // Declarations in source order: inputs, client bindings, service instances, taint propagation.
  for (const decl of collect(body, ts.isVariableDeclaration)) {
    if (!decl.initializer) continue;
    const init = clientCreatingOperand(decl.initializer);
    const names = boundNames(decl.name);
    const text = init.getText(sf);
    aliasLocal(frame, decl.name, init);
    const who = identityBinding(p, frame, init, scope);
    if (who !== undefined)
      for (const nm of identityNamesOf(decl.name)) frame.identities.set(nm, who);
    // A client first: `createClient(url, anon, { global: { headers: { Authorization:
    // req.headers.get(…) } } })` reads a header, but what it binds is a client, not input.
    const client = ts.isCallExpression(init) ? classifyCall(p, init, sf, scope, frame, 0) : null;
    if (client && ts.isIdentifier(decl.name)) {
      frame.clients.set(decl.name.text, client);
      continue;
    }
    // Rows returned by a query are data, not input, even when the query filters by a request value.
    const rowsOfQuery = ts.isCallExpression(init) && (isQueryChain(init) || isDbChain(init, frame));
    if (frame.depth === 0 && !rowsOfQuery) {
      if (/^(params|context\.params|ctx\.params|props\.params)$/.test(text)) {
        handlerInput("route_param", names, decl);
        continue;
      }
      if (ts.isCallExpression(init) && isRequestCall(text)) {
        handlerInput("body", names, decl);
        continue;
      }
      if (/searchParams\.get\(|\.searchParams$|^new URL\(/.test(text)) {
        handlerInput("query", names, decl);
        continue;
      }
      if (/headers\.get\(/.test(text)) {
        handlerInput("header", names, decl);
        continue;
      }
    }
    // A cookie or a request header is caller-supplied wherever it is read, not only in the handler:
    // custom sessions live in helpers (`getAdvertiserFromCookies()` -> `.eq("token", token)`), and
    // without this the credential lookup that authenticates the caller is invisible.
    if (CALLER_READ.test(text)) {
      if (frame.depth === 0) handlerInput("header", names, decl);
      else bindInput(names, false);
      continue;
    }
    if (ts.isCallExpression(init)) {
      const inst = instanceOfCall(p, init, frame, scope);
      if (inst && ts.isIdentifier(decl.name)) {
        frame.instances.set(decl.name.text, inst);
        continue;
      }
      if (rowsOfQuery) continue;
      // What a helper returns from user input is user input (`const body = await parseBody(req)`),
      // unless the helper establishes identity (`const user = await getUserFromRequest(req)`).
      if (returnsIdentity(p, init, scope)) continue;
      const args = init.arguments.map((a) => argBinding(p, a, frame));
      if (args.some((a) => a.tainted || a.isRequest) || receiverTainted(frame, init)) {
        // A helper of this repository returns what its body shows: rows of a query, identity, or
        // an object whose tainted properties are known. Anything unresolved returns its input.
        const rt = returnTaint(p, init, frame, scope, 0);
        if (rt === null || (rt.tainted && rt.props === null)) {
          bindInput(names, isWholeInput(init, wholeContext(p, frame)));
        } else if (rt.tainted && rt.props !== null) {
          if (ts.isIdentifier(decl.name))
            frame.partialInputs.set(decl.name.text, new Set(rt.props));
          else bindPatternFrom(frame, decl.name, rt.props);
        }
      }
    } else if (isPrismaNew(init) && ts.isIdentifier(decl.name)) {
      frame.clients.set(decl.name.text, {
        kind: "direct_db",
        name: decl.name.text,
        location: loc(init),
      });
    } else if (
      ts.isNewExpression(init) &&
      ts.isIdentifier(init.expression) &&
      scope.get(init.expression.text)?.kind === "class"
    ) {
      const cs = scope.get(init.expression.text);
      if (cs?.kind === "class" && ts.isIdentifier(decl.name)) {
        frame.instances.set(decl.name.text, {
          cls: cs.cls,
          facts: cs.facts,
          ctorArgs: (init.arguments ?? []).map((a) => argBinding(p, a, frame)),
        });
      }
    } else if (ts.isIdentifier(init)) {
      const c = frame.clients.get(init.text);
      if (c && ts.isIdentifier(decl.name)) frame.clients.set(decl.name.text, c);
      const i = frame.instances.get(init.text);
      if (i && ts.isIdentifier(decl.name)) frame.instances.set(decl.name.text, i);
      if (frame.inputNames.has(init.text)) {
        // `const payload = body;` keeps the taint (and stays a named input in the handler itself).
        if (frame.depth === 0) for (const nm of names) addInput("body", nm, decl, true);
        bindInput(names, frame.wholeNames.has(init.text));
      } else {
        const partial = frame.partialInputs.get(init.text);
        if (partial && ts.isIdentifier(decl.name)) {
          frame.partialInputs.set(decl.name.text, new Set(partial));
        } else if (partial) bindPatternFrom(frame, decl.name, partial);
      }
    } else if (!isChainWithQuery(init) && derivedIn(frame, init)) {
      bindInput(names, isWholeInput(init, wholeContext(p, frame)));
    }
  }
  // `dev = data` after `let dev = null`: a variable holds an identity only when every non-literal
  // value assigned to it is one.
  const assigned = new Map<string, Array<string | null | undefined>>();
  for (const asg of collect(body, ts.isBinaryExpression)) {
    if (asg.operatorToken.kind !== ts.SyntaxKind.EqualsToken || !ts.isIdentifier(asg.left))
      continue;
    if (isLiteralValue(unwrap(asg.right))) continue;
    const list = assigned.get(asg.left.text) ?? [];
    list.push(identityBinding(p, frame, asg.right, scope));
    assigned.set(asg.left.text, list);
  }
  for (const [name, whos] of assigned) {
    const [first] = whos;
    if (first !== undefined && whos.every((w) => w !== undefined))
      frame.identities.set(name, first);
    else frame.identities.delete(name);
  }
  if (frame.depth === 0) {
    walk(body, (n) => {
      if (
        ts.isPropertyAccessExpression(n) &&
        ts.isIdentifier(n.expression) &&
        n.expression.text === "params"
      ) {
        addInput("route_param", n.name.text, n, false);
      }
      return undefined;
    });
  }
}

function analyzeFrame(p: Project, frame: Frame, acc: Acc): void {
  const { rel, sf, fn } = frame;
  const scope = scopeOf(p, frame.facts);
  const loc = (n: ts.Node): FileRef => ({ file: rel, line: lineOf(sf, n) });
  const body: ts.Node = fn.body ?? fn;

  bindDeclarations(p, frame, acc);

  // `db.transaction(async (tx) => …)` / `prisma.$transaction(async (tx) => …)`: the callback's client is the outer one.
  for (const call of collect(body, ts.isCallExpression)) {
    const callee = call.expression;
    if (!ts.isPropertyAccessExpression(callee) || !/^\$?transaction$/.test(callee.name.text))
      continue;
    if (!ts.isIdentifier(callee.expression)) continue;
    const outer = frame.clients.get(callee.expression.text);
    const fn = call.arguments
      .map((a) => unwrap(a))
      .find((a) => ts.isArrowFunction(a) || ts.isFunctionExpression(a));
    const param =
      fn && (ts.isArrowFunction(fn) || ts.isFunctionExpression(fn)) ? fn.parameters[0] : undefined;
    if (outer && param && ts.isIdentifier(param.name)) frame.clients.set(param.name.text, outer);
  }

  // Auth checks.
  const isSessionCall = (call: ts.CallExpression): boolean => callsSession(p, call, sf, scope);
  for (const call of collect(body, ts.isCallExpression)) {
    if (isSessionCall(call)) acc.authChecks.push({ ...loc(call), kind: "session" });
  }
  // Role gates (ADR-001): `if (!isAdminEmail(user.email)) return 401` on a session binding.
  // A row the caller's identity selected speaks for the session too (`profil.rolle` of the caller's
  // own profile); the check then carries the table and column, so the rules can ask who writes it.
  const sessionNames = sessionNamesIn(body, isSessionCall);
  for (const name of frame.identities.keys()) sessionNames.add(name);
  for (const gate of roleGatesIn(body, sessionNames)) {
    if (gate.exit === "return" && !frame.exitPropagates) continue;
    const [root, ...rest] = gate.source.split(".");
    const table = root === undefined ? undefined : frame.identities.get(root);
    const column = rest[rest.length - 1];
    acc.roleChecks.push({
      ...loc(gate.node),
      source: gate.source,
      text: gate.node.expression.getText(sf).replace(/\s+/g, " ").slice(0, 160),
      ...(typeof table === "string" && column !== undefined ? { table, column } : {}),
    });
  }
  // A request credential compared with (or verified by) a server secret, deciding the request's fate.
  for (const check of secretChecksIn(fn, sf)) {
    acc.authChecks.push({ ...loc(check.node), kind: "secret" });
  }

  // Metadata accesses: user_metadata is end-user editable, app_metadata is not.
  for (const pa of collect(body, ts.isPropertyAccessExpression)) {
    const inner = pa.expression;
    if (
      ts.isPropertyAccessExpression(inner) &&
      (inner.name.text === "user_metadata" || inner.name.text === "app_metadata")
    ) {
      acc.metadataAccesses.push({
        path: pa.getText(sf),
        bucket: inner.name.text,
        field: pa.name.text,
        location: loc(pa),
      });
    }
  }

  // Query chains: Supabase (PostgREST), Drizzle and Prisma (direct database connections).
  const seen = new Set<number>();
  const clientOf = (
    root: ts.Expression,
  ): { binding: ClientBinding | null; name: string | null } => {
    const u = unwrap(root);
    if (ts.isIdentifier(u)) {
      const b = frame.clients.get(u.text) ?? null;
      return { binding: b, name: b ? null : u.text };
    }
    if (ts.isCallExpression(u)) {
      const b = classifyCall(p, u, sf, scope, frame, 0);
      return { binding: b, name: b ? null : u.expression.getText(sf) };
    }
    if (ts.isPropertyAccessExpression(u) && u.expression.kind === ts.SyntaxKind.ThisKeyword) {
      const b = frame.thisProps.get(u.name.text)?.client ?? null;
      return { binding: b, name: b ? null : u.getText(sf) };
    }
    return { binding: null, name: u.getText(sf) };
  };
  const tableSym = (e: ts.Expression | undefined): string | null => {
    if (!e) return null;
    const u = unwrap(e);
    if (ts.isIdentifier(u)) {
      const sym = scope.get(u.text);
      return sym?.kind === "table" ? sym.table : null;
    }
    if (ts.isPropertyAccessExpression(u) && ts.isIdentifier(u.expression)) {
      const ns = scope.get(u.expression.text);
      if (ns?.kind === "namespace") {
        const sym = exportedSym(p, ns.facts, u.name.text, 0);
        return sym?.kind === "table" ? sym.table : null;
      }
    }
    return null;
  };
  // The expression behind each filter value, for matching a guard read to the query it guards.
  const filterValues = new WeakMap<QueryFilter, ts.Expression>();
  const valued = (f: QueryFilter, v: ts.Expression | null | undefined): QueryFilter => {
    if (v) filterValues.set(f, v);
    return f;
  };
  const toFilter = (f: OrmFilter): QueryFilter =>
    valued(
      {
        method: f.method,
        column: f.column,
        valueText: f.value ? f.value.getText(sf) : f.text,
        inputDerived: f.value ? derivedIn(frame, f.value) : false,
        ...(f.value && identityOf(frame, f.value) !== undefined ? { identity: true } : {}),
      },
      f.value,
    );
  const payloadOf = (arg: ts.Expression | null | undefined): QueryPayload | null =>
    arg
      ? {
          text: arg.getText(sf).replace(/\s+/g, " ").slice(0, 200),
          inputDerived: derivedIn(frame, arg),
          wholeInput: isWholeInput(arg, wholeContext(p, frame)),
        }
      : null;
  interface Parsed {
    anchor: ts.Node;
    table: string;
    operation: QueryOperation;
    filters: QueryFilter[];
    payload: QueryPayload | null;
    clientRoot: ts.Expression;
  }
  // Supabase Storage: client.storage.from(bucket).download(path) and friends, rows of storage.objects.
  const storageHandles = storageBindingsIn(body);
  let callerScope: CallerScope | null = null;
  const pushStorage = (st: StorageCall, call: ts.CallExpression): void => {
    const op = st.op;
    if (!op || seen.has(op.node.pos)) return;
    seen.add(op.node.pos);
    callerScope ??= new CallerScope(body, frame.inputNames);
    const { binding, name: clientName } = clientOf(st.clientRoot);
    const query: SupabaseQuery = {
      table: "storage.objects",
      operation: STORAGE_OPS[op.name] ?? "unknown",
      client: binding?.kind ?? "unknown",
      clientName: binding?.name ?? clientName,
      clientLocation: binding?.location ?? null,
      filters: [],
      payload: null,
      location: loc(op.node),
      text: call.getText(sf).replace(/\s+/g, " ").slice(0, 200),
      storage: storageAccessOf(op, bucketName(st.bucketArg, sf), sf, callerScope, (e) =>
        derivedIn(frame, e),
      ),
    };
    if (frame.via.length > 0) query.via = frame.via;
    acc.queries.push(query);
  };
  const supabaseFilters = (segments: readonly ChainSegment[]): QueryFilter[] => {
    const filters: QueryFilter[] = [];
    for (const s of segments) {
      if (!FILTER_METHODS.has(s.name)) continue;
      const firstArg = s.args[0];
      if (s.name === "match" && firstArg && ts.isObjectLiteralExpression(firstArg)) {
        for (const pr of firstArg.properties) {
          if (ts.isPropertyAssignment(pr)) {
            const f: QueryFilter = {
              method: "match",
              column: pr.name.getText(sf).replace(/['"]/g, ""),
              valueText: pr.initializer.getText(sf),
              inputDerived: derivedIn(frame, pr.initializer),
              ...(identityOf(frame, pr.initializer) !== undefined ? { identity: true } : {}),
            };
            filters.push(valued(f, pr.initializer));
          }
        }
        continue;
      }
      const val = s.args[1];
      const f: QueryFilter = {
        method: s.name,
        column: stringLiteralValue(firstArg),
        valueText: val ? val.getText(sf) : "",
        inputDerived: val ? derivedIn(frame, val) : false,
        ...(val && identityOf(frame, val) !== undefined ? { identity: true } : {}),
      };
      filters.push(valued(f, val));
    }
    return filters;
  };
  // Query builders: `let q = admin.from("t").select().eq("id", id); if (!isAdmin) q = q.eq("user_id", user.id)`.
  const builders = new Map<string, SupabaseQuery>();
  const bindBuilder = (tail: ts.CallExpression, query: SupabaseQuery): void => {
    const { node, parent } = outerOf(tail);
    if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
      builders.set(parent.name.text, query);
    } else if (
      parent &&
      ts.isBinaryExpression(parent) &&
      parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      parent.right === node &&
      ts.isIdentifier(parent.left)
    ) {
      builders.set(parent.left.text, query);
    }
  };
  for (const call of collect(body, ts.isCallExpression)) {
    if (!isChainTail(call)) continue;
    const chain = flattenChain(call);
    const storageCall = storageCallOf(chain, storageHandles);
    if (storageCall) {
      // A storage chain is never a PostgREST query, even when it is not an object access (getPublicUrl).
      pushStorage(storageCall, call);
      continue;
    }
    const root = unwrap(chain.root);
    const builder = ts.isIdentifier(root) ? builders.get(root.text) : undefined;
    if (builder) {
      // Filters added to a saved builder belong to its query. One added under an `if` counts only
      // when the caller cannot steer the condition: `if (!isAdmin(user))` yes, `if (!body.all)` no.
      const condition = enclosingCondition(call, body);
      if (!condition || !derivedIn(frame, condition)) {
        const note = condition ? ` (when ${condition.getText(sf).replace(/\s+/g, " ")})` : "";
        for (const f of supabaseFilters(chain.segments)) {
          builder.filters.push(note ? { ...f, valueText: `${f.valueText}${note}` } : f);
        }
      }
      bindBuilder(call, builder);
      continue;
    }
    const first = chain.segments[0];
    const fromIdx = chain.segments.findIndex((s) => s.name === "from");
    const rpcIdx = chain.segments.findIndex((s) => s.name === "rpc");
    const fromSeg = fromIdx >= 0 ? chain.segments[fromIdx] : undefined;
    const fromTable = fromSeg ? stringLiteralValue(fromSeg.args[0]) : null;
    const whereFilters = (): QueryFilter[] =>
      chain.segments
        .filter((s) => s.name === "where")
        .flatMap((s) => drizzleFilters(s.args[0], sf))
        .map(toFilter);
    let parsed: Parsed | null = null;

    const drizzleTable = fromSeg ? tableSym(fromSeg.args[0]) : null;
    if ((fromSeg && drizzleTable === null) || (rpcIdx >= 0 && fromIdx < 0)) {
      // Supabase: client.from("table").select().eq(...)  /  client.rpc("fn", ...); dynamic table names stay "(dynamic)"
      const anchorIdx = fromSeg && drizzleTable === null ? fromIdx : rpcIdx;
      const anchor = chain.segments[anchorIdx];
      if (!anchor) continue;
      const after = chain.segments.slice(anchorIdx + 1);
      let operation: QueryOperation = anchorIdx === fromIdx ? "unknown" : "rpc";
      let payload: QueryPayload | null = null;
      for (const s of after) {
        if (OPERATIONS.has(s.name as QueryOperation)) {
          operation = s.name as QueryOperation;
          if (WRITE_OPERATIONS.has(operation)) payload = payloadOf(s.args[0]);
          break;
        }
      }
      const filters = supabaseFilters(after);
      parsed = {
        anchor: anchor.node,
        table: fromTable ?? stringLiteralValue(anchor.args[0]) ?? "(dynamic)",
        operation,
        filters,
        payload,
        clientRoot: chain.root,
      };
    } else if (fromSeg && drizzleTable !== null) {
      // Drizzle: db.select().from(invoices).where(eq(invoices.id, id))
      parsed = {
        anchor: fromSeg.node,
        table: drizzleTable,
        operation: "select",
        filters: whereFilters(),
        payload: null,
        clientRoot: chain.root,
      };
    } else if (first && DRIZZLE_WRITE_OPS[first.name] && tableSym(first.args[0]) !== null) {
      // Drizzle: db.insert(t).values(x) / db.update(t).set(x).where(...) / db.delete(t).where(...)
      const op = DRIZZLE_WRITE_OPS[first.name] ?? "unknown";
      const payloadSeg = chain.segments.find((s) => s.name === "values" || s.name === "set");
      parsed = {
        anchor: first.node,
        table: tableSym(first.args[0]) ?? "(dynamic)",
        operation: op,
        filters: whereFilters(),
        payload: payloadOf(payloadSeg?.args[0]),
        clientRoot: chain.root,
      };
    } else if (
      first &&
      DRIZZLE_QUERY_API.has(first.name) &&
      ts.isPropertyAccessExpression(root) &&
      ts.isPropertyAccessExpression(root.expression) &&
      root.expression.name.text === "query"
    ) {
      // Drizzle relational API: db.query.invoices.findFirst({ where: eq(...) })
      const key = root.name.text;
      parsed = {
        anchor: first.node,
        table: p.drizzleTablesByExport.get(key) ?? key,
        operation: "select",
        filters: drizzleFilters(objectProperty(first.args[0], "where") ?? undefined, sf).map(
          toFilter,
        ),
        payload: null,
        clientRoot: root.expression.expression,
      };
    } else if (
      first &&
      PRISMA_OPS[first.name] &&
      ts.isPropertyAccessExpression(root) &&
      ts.isIdentifier(root.expression) &&
      clientOf(root.expression).binding?.kind === "direct_db"
    ) {
      // Prisma: prisma.invoice.findUnique({ where: { id } })
      const accessor = root.name.text;
      const arg = first.args[0];
      parsed = {
        anchor: first.node,
        table: p.prismaModels.get(accessor) ?? accessor.charAt(0).toUpperCase() + accessor.slice(1),
        operation: PRISMA_OPS[first.name] ?? "unknown",
        filters: prismaWhereFilters(objectProperty(arg, "where"), sf).map(toFilter),
        payload: payloadOf(objectProperty(arg, "data")),
        clientRoot: root.expression,
      };
    }
    if (!parsed) continue;
    if (seen.has(parsed.anchor.pos)) continue;
    seen.add(parsed.anchor.pos);
    const { binding, name: clientName } = clientOf(parsed.clientRoot);
    const query: SupabaseQuery = {
      table: parsed.table,
      operation: parsed.operation,
      client: binding?.kind ?? "unknown",
      clientName: binding?.name ?? clientName,
      clientLocation: binding?.location ?? null,
      filters: parsed.filters,
      payload: parsed.payload,
      location: loc(parsed.anchor),
      text: call.getText(sf).replace(/\s+/g, " ").slice(0, 200),
    };
    if (frame.via.length > 0) query.via = frame.via;
    if (pushQuery(acc, query) === query) {
      const rowExit = missingRowExit(
        call,
        chain.segments.map((s) => s.name),
      );
      // `if (!row || row.user_id !== user.id) return 404`: ownership checked in code after the read.
      const checks: QueryFilter[] = rowComparisons(call)
        .filter((c) => c.exit === "throw" || frame.exitPropagates)
        .map((c) => ({
          method: "compare",
          column: c.column,
          valueText: c.value.getText(sf).replace(/\s+/g, " "),
          inputDerived: derivedIn(frame, c.value),
          ...(identityOf(frame, c.value) !== undefined ? { identity: true } : {}),
        }));
      if (checks.length > 0) query.ownerChecks = checks;
      acc.reads.push({
        query,
        keys: query.filters.map((f) => {
          const v = filterValues.get(f);
          return v ? valueKey(frame, v) : null;
        }),
        order: [...frame.pathPos, parsed.anchor.getStart(sf)],
        exits: rowExit === "throw" || (rowExit === "return" && frame.exitPropagates),
        checks,
      });
      bindBuilder(call, query);
    }
    // Looking the caller up by a request credential (`api_keys.key_hash = sha256(bearer)`) is the
    // authentication step itself.
    if (query.filters.some((f) => f.inputDerived && isCredentialColumn(f.column))) {
      acc.authChecks.push({ ...query.location, kind: "credential" });
    }
  }

  // Follow calls into helpers, services and methods of this repository.
  if (frame.depth >= MAX_DEPTH) return;
  for (const call of collect(body, ts.isCallExpression)) {
    const target = callTarget(p, call, frame, scope);
    if (!target) continue;
    const child = childFrame(p, call, target, frame);
    if (!child) continue;
    // Same helper, same bindings: analysed once per handler.
    const key = `${target.facts.file}#${target.name}#${frameSignature(child)}`;
    if (acc.visited.has(key)) continue;
    acc.visited.add(key);
    analyzeFrame(p, child, acc);
  }
}

/** The callee's frame for one call site: parameters bound to what the caller passes. */
function childFrame(
  p: Project,
  call: ts.CallExpression,
  target: CallTarget,
  frame: Frame,
): Frame | null {
  const tsf = p.sources.get(target.facts.file);
  if (!tsf) return null;
  const child: Frame = {
    rel: target.facts.file,
    sf: tsf,
    facts: target.facts,
    fn: target.fn,
    depth: frame.depth + 1,
    via: [...frame.via, `${target.name} (${target.facts.file}:${lineOf(tsf, target.fn)})`],
    inputNames: new Set(),
    wholeNames: new Set(),
    partialInputs: new Map(),
    reqNames: new Set(),
    clients: new Map(),
    instances: new Map(),
    cls: target.cls,
    thisProps: target.thisProps,
    key: `${target.facts.file}#${target.name}@${call.getStart(frame.sf)}`,
    aliases: new Map(),
    pathPos: [...frame.pathPos, call.getStart(frame.sf)],
    exitPropagates: frame.exitPropagates && callResultChecked(call),
    identities: new Map(),
  };
  const cx = wholeContext(p, frame);
  target.fn.parameters.forEach((param, i) => {
    const arg = call.arguments[i];
    const ab = argBinding(p, arg, frame);
    const names = boundNames(param.name);
    const head = names[0];
    if (ab.client && head !== undefined && ts.isIdentifier(param.name)) {
      child.clients.set(head, ab.client);
    }
    if (ab.instance && head !== undefined && ts.isIdentifier(param.name)) {
      child.instances.set(head, ab.instance);
    }
    for (const nm of names) if (ab.isRequest) child.reqNames.add(nm);
    // The caller's identity handed over (`requireOwner(user, id)`) is still the caller's identity.
    const who = arg ? identityOf(frame, arg) : undefined;
    if (who !== undefined && ts.isIdentifier(param.name))
      child.identities.set(param.name.text, who);
    if (ab.tainted) {
      bindParamTaint(child, param.name, arg, frame);
      for (const nm of wholeParamNames(param.name, arg, cx)) {
        child.inputNames.add(nm);
        child.wholeNames.add(nm);
      }
      // Only user-controlled values can be a guarded id, so only they are named across frames.
      aliasParam(child, param.name, arg, frame);
    }
  });
  return child;
}

/** What the caller bound into a frame, for memoising per-helper work. */
function frameSignature(child: Frame): string {
  return [
    ...[...child.clients].map(([n, c]) => `${n}=${c.kind}`),
    ...[...child.inputNames].map((n) => `${n}!${child.wholeNames.has(n) ? "*" : ""}`),
    ...[...child.partialInputs].map(([n, s]) => `${n}.{${[...s].sort().join("|")}}`),
    ...[...child.reqNames].map((n) => `${n}?`),
    ...[...child.identities].map(([n, t]) => `${n}@${t ?? ""}`),
    ...[...child.thisProps].map(([n, b]) => `this.${n}=${b.client?.kind ?? "-"}`),
    ...[...child.aliases].map(([n, k]) => `${n}~${k}`),
    `exit=${child.exitPropagates}`,
  ]
    .sort()
    .join(",");
}

/**
 * What a helper's result carries back to its caller. `tainted: false`: nothing the caller controls
 * (rows of a query, identity, literals, an object built from those). `props`: the properties of a
 * returned object literal that do carry input (`{ id: body.id, row }` taints only `.id`); null
 * when the whole value does.
 */
interface ReturnTaint {
  tainted: boolean;
  props: Set<string> | null;
}

const CLEAN: ReturnTaint = { tainted: false, props: null };
const TAINTED: ReturnTaint = { tainted: true, props: null };
/** Helper calls followed for their return value: caller -> helper -> helper. */
const MAX_RETURN_DEPTH = 2;

/** The branches an expression can evaluate to: `a ?? b`, `c ? a : b`, `a || b`. */
function branchesOf(e: ts.Expression): ts.Expression[] {
  const u = unwrap(e);
  if (ts.isConditionalExpression(u)) return [...branchesOf(u.whenTrue), ...branchesOf(u.whenFalse)];
  if (
    ts.isBinaryExpression(u) &&
    (u.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken ||
      u.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
      u.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken)
  ) {
    return [...branchesOf(u.left), ...branchesOf(u.right)];
  }
  return [u];
}

function isLiteralValue(e: ts.Expression): boolean {
  return (
    ts.isStringLiteralLike(e) ||
    ts.isNumericLiteral(e) ||
    e.kind === ts.SyntaxKind.NullKeyword ||
    e.kind === ts.SyntaxKind.TrueKeyword ||
    e.kind === ts.SyntaxKind.FalseKeyword ||
    (ts.isIdentifier(e) && e.text === "undefined")
  );
}

function mergeTaint(a: ReturnTaint, b: ReturnTaint): ReturnTaint {
  if (!a.tainted) return b;
  if (!b.tainted) return a;
  if (a.props === null || b.props === null) return TAINTED;
  return { tainted: true, props: new Set([...a.props, ...b.props]) };
}

/** Taint of one returned branch, evaluated in the callee's own frame after its declarations are bound. */
function leafTaint(
  p: Project,
  leaf: ts.Expression,
  child: Frame,
  scope: Map<string, Sym>,
  depth: number,
): ReturnTaint {
  if (isLiteralValue(leaf)) return CLEAN;
  if (ts.isObjectLiteralExpression(leaf)) {
    const props = taintedProperties(child, leaf);
    if (props === null) return TAINTED;
    return props.size === 0 ? CLEAN : { tainted: true, props };
  }
  if (ts.isCallExpression(leaf)) {
    // Rows of a query and the caller's identity are data, whatever filtered or produced them.
    if (isChainWithQuery(leaf) || isDbChain(leaf, child)) return CLEAN;
    if (returnsIdentity(p, leaf, scope)) return CLEAN;
    const nested = returnTaint(p, leaf, child, scope, depth + 1);
    if (nested !== null) return nested;
  }
  return derivedIn(child, leaf) ? TAINTED : CLEAN;
}

/**
 * The return taint of a helper call, or null when the callee is not a function of this repository
 * (an SDK or an unresolvable import: its result is assumed to carry whatever input it was given).
 * The callee's declarations are bound with the caller's arguments first, so `const row = await
 * findByHash(hash(presented))` is clean (`row` is a query result) while `return body.id` is not.
 */
function returnTaint(
  p: Project,
  call: ts.CallExpression,
  frame: Frame,
  scope: Map<string, Sym>,
  depth: number,
): ReturnTaint | null {
  if (depth > MAX_RETURN_DEPTH) return null;
  const target = callTarget(p, call, frame, scope);
  if (!target) return null;
  const child = childFrame(p, call, target, frame);
  if (!child) return null;
  const key = `${target.facts.file}#${target.name}#${frameSignature(child)}`;
  const cached = p.returnTaints.get(key);
  if (cached !== undefined) return cached;
  // A helper that (indirectly) calls itself is left to the caller's assumption.
  p.returnTaints.set(key, null);
  const scratch: Acc = {
    inputs: [],
    authChecks: [],
    roleChecks: [],
    queries: [],
    metadataAccesses: [],
    visited: new Set(),
    reads: [],
  };
  bindDeclarations(p, child, scratch);
  const childScope = scopeOf(p, child.facts);
  let out: ReturnTaint = CLEAN;
  for (const ret of ownReturns(target.fn)) {
    for (const leaf of branchesOf(ret)) {
      out = mergeTaint(out, leafTaint(p, leaf, child, childScope, depth));
      if (out.tainted && out.props === null) break;
    }
  }
  p.returnTaints.set(key, out);
  return out;
}

/**
 * One query, one entry per handler. A helper reached through two call paths with different bindings
 * is analysed twice; its query is kept once, user-controlled wherever any path made it so.
 */
function pushQuery(acc: Acc, q: SupabaseQuery): SupabaseQuery {
  const same = acc.queries.find(
    (x) =>
      x.location.file === q.location.file &&
      x.location.line === q.location.line &&
      x.text === q.text &&
      x.client === q.client &&
      x.clientName === q.clientName &&
      x.filters.length === q.filters.length,
  );
  if (!same) {
    acc.queries.push(q);
    return q;
  }
  q.filters.forEach((f, i) => {
    const mine = same.filters[i];
    if (mine && f.inputDerived) mine.inputDerived = true;
  });
  if (same.payload && q.payload) {
    same.payload.inputDerived ||= q.payload.inputDerived;
    same.payload.wholeInput ||= q.payload.wholeInput;
  }
  return same;
}

/** `input.contactId` -> "input.contactId"; null for anything but identifiers and property reads. */
function dottedPath(e: ts.Expression): string | null {
  const u = unwrap(e);
  if (ts.isIdentifier(u)) return u.text;
  if (ts.isPropertyAccessExpression(u)) {
    const base = dottedPath(u.expression);
    return base === null ? null : `${base}.${u.name.text}`;
  }
  return null;
}

/**
 * The value an expression holds, named the same in every frame: a helper parameter is named by the
 * caller's argument (`flowId` in `requireOwnership(flowId)` called with `id` is the handler's `id`).
 */
function valueKey(frame: Frame, e: ts.Expression): string | null {
  const path = dottedPath(e);
  if (path === null) return null;
  const parts = path.split(".");
  for (let i = parts.length; i > 0; i--) {
    const alias = frame.aliases.get(parts.slice(0, i).join("."));
    if (alias !== undefined) return [alias, ...parts.slice(i)].join(".");
  }
  return `${frame.key}:${path}`;
}

/** `const flowId = id`, `const { id } = await params`: the new name holds the same value. */
function aliasLocal(frame: Frame, name: ts.BindingName, init: ts.Expression): void {
  const key = valueKey(frame, init);
  if (key === null) return;
  if (ts.isIdentifier(name)) {
    frame.aliases.set(name.text, key);
    return;
  }
  if (!ts.isObjectBindingPattern(name)) return;
  for (const el of name.elements) {
    const k = propertyKeyOf(el.propertyName ?? el.name);
    if (k !== null && !el.dotDotDotToken && ts.isIdentifier(el.name)) {
      frame.aliases.set(el.name.text, `${key}.${k}`);
    }
  }
}

/** Names a callee parameter by the caller's argument, property by property for object literals. */
function aliasParam(
  child: Frame,
  param: ts.BindingName,
  arg: ts.Expression | undefined,
  frame: Frame,
): void {
  if (!arg) return;
  const u = unwrap(arg);
  if (ts.isIdentifier(param)) {
    const key = valueKey(frame, arg);
    if (key !== null) child.aliases.set(param.text, key);
    else if (ts.isObjectLiteralExpression(u)) {
      for (const pr of u.properties) {
        const k = propertyKeyOf(pr.name);
        const v = ts.isPropertyAssignment(pr)
          ? pr.initializer
          : ts.isShorthandPropertyAssignment(pr)
            ? pr.name
            : undefined;
        const vk = k !== null && v ? valueKey(frame, v) : null;
        if (k !== null && vk !== null) child.aliases.set(`${param.text}.${k}`, vk);
      }
    }
    return;
  }
  if (!ts.isObjectBindingPattern(param)) return;
  const base = valueKey(frame, arg);
  for (const el of param.elements) {
    const k = propertyKeyOf(el.propertyName ?? el.name);
    if (k === null || el.dotDotDotToken || !ts.isIdentifier(el.name)) continue;
    if (base !== null) {
      child.aliases.set(el.name.text, `${base}.${k}`);
      continue;
    }
    if (!ts.isObjectLiteralExpression(u)) continue;
    const pr = u.properties.find((x) => propertyKeyOf(x.name) === k);
    const v =
      pr && ts.isPropertyAssignment(pr)
        ? pr.initializer
        : pr && ts.isShorthandPropertyAssignment(pr)
          ? pr.name
          : undefined;
    const vk = v ? valueKey(frame, v) : null;
    if (vk !== null) child.aliases.set(el.name.text, vk);
  }
}

/** The `if` whose branch contains `node`, up to the function body; null when the node runs unconditionally. */
function enclosingCondition(node: ts.Node, body: ts.Node): ts.Expression | null {
  let child: ts.Node = node;
  let cur: ts.Node | undefined = node.parent;
  while (cur && cur !== body && !isFunctionLikeNode(cur)) {
    if (ts.isIfStatement(cur) && cur.expression !== child) return cur.expression;
    child = cur;
    cur = cur.parent;
  }
  return null;
}

const normalizeColumn = (c: string | null): string => (c ?? "").toLowerCase().replace(/_/g, "");

function singular(table: string): string {
  if (table.endsWith("ies")) return `${table.slice(0, -3)}y`;
  if (table.endsWith("ses") || table.endsWith("xes")) return table.slice(0, -2);
  return table.endsWith("s") ? table.slice(0, -1) : table;
}

/** `automation_id` names a row of `automations` (or `automation`). */
function columnNamesTable(column: string, table: string): boolean {
  const c = normalizeColumn(column);
  if (!c.endsWith("id") || c === "id") return false;
  const stem = c.slice(0, -2);
  const t = normalizeColumn(table);
  return stem === t || stem === singular(t);
}

interface GuardMatch {
  read: GuardableRead;
  column: string;
  parent?: QueryGuard["parent"];
}

/**
 * The read `g` guards the query `q` when both filter by the same value: the same column of the
 * same table (`flows.id` read, then `flows.id` deleted), or the parent's id and a column of the
 * child that refers to it (`automations.id` read, then `automation_steps.automation_id`), by a
 * foreign key in the migrations or by the column's name.
 */
function guardMatch(
  q: GuardableRead,
  g: GuardableRead,
  tables: ReadonlyMap<string, RlsTable>,
): GuardMatch | null {
  const qTable = q.query.table.toLowerCase();
  const gTable = g.query.table.toLowerCase();
  const info = tables.get(qTable);
  for (let i = 0; i < q.query.filters.length; i += 1) {
    const f = q.query.filters[i];
    const k = q.keys[i];
    if (!f?.inputDerived || !f.column || k === null || k === undefined) continue;
    const j = g.keys.indexOf(k);
    const gf = j >= 0 ? g.query.filters[j] : undefined;
    if (!gf) continue;
    if (qTable === gTable) {
      if (normalizeColumn(gf.column) === normalizeColumn(f.column))
        return { read: g, column: f.column };
      continue;
    }
    const ref = info?.columnInfo?.find((c) => c.name === f.column?.toLowerCase())?.references;
    if (ref && ref.table === gTable && normalizeColumn(ref.column) === normalizeColumn(gf.column)) {
      return {
        read: g,
        column: f.column,
        parent: { table: g.query.table, column: gf.column ?? "id", how: "foreign key" },
      };
    }
    if (normalizeColumn(gf.column) === "id" && columnNamesTable(f.column, gTable)) {
      return {
        read: g,
        column: f.column,
        parent: { table: g.query.table, column: gf.column ?? "id", how: "column name" },
      };
    }
  }
  return null;
}

/**
 * Links each query to an earlier read of the same row, or of its parent row, by the same value
 * (the guard), preferring a read whose missing row stops the entry point. Rules decide whether the
 * guard ties the row to the caller.
 */
function linkGuards(reads: readonly GuardableRead[], tables: ReadonlyMap<string, RlsTable>): void {
  for (const q of reads) {
    let best: GuardMatch | null = null;
    for (const g of reads) {
      if (g === q || !["select", "unknown"].includes(g.query.operation)) continue;
      if (compareOrder(g.order, q.order) >= 0) continue;
      const m = guardMatch(q, g, tables);
      if (!m) continue;
      const stops = (r: GuardableRead): boolean => r.exits || r.checks.length > 0;
      if (!best || (stops(m.read) && !stops(best.read))) best = m;
    }
    if (!best) continue;
    const g = best.read.query;
    q.query.guard = {
      location: g.location,
      table: g.table,
      client: g.client,
      clientName: g.clientName,
      filters: g.filters,
      column: best.column,
      // A row that fails the comparison stops the entry point too; a missing one fails it as well.
      exitsWhenMissing: best.read.exits || best.read.checks.length > 0,
      text: g.text,
      ...(g.via ? { via: g.via } : {}),
      ...(best.read.checks.length > 0 ? { checks: best.read.checks } : {}),
      ...(best.parent ? { parent: best.parent } : {}),
    };
  }
}

function isChainWithQuery(e: ts.Expression): boolean {
  return ts.isCallExpression(e) && isQueryChain(e);
}

/** A call chain rooted at a bound database client (`db.query.x.findFirst()`, `prisma.invoice.findUnique()`): rows, not input. */
function isDbChain(call: ts.CallExpression, frame: Frame): boolean {
  const root = unwrap(flattenChain(call).root);
  let base: ts.Expression = root;
  while (ts.isPropertyAccessExpression(base)) base = base.expression;
  return ts.isIdentifier(base) && frame.clients.has(base.text);
}

const IDENTITY_CALLEE = /\.auth\.|user|session|claims|auth|principal|viewer/i;

/** Calls that resolve who the caller is: their result is trusted identity, not attacker input. */
function returnsIdentity(p: Project, call: ts.CallExpression, scope: Map<string, Sym>): boolean {
  if (symOfCallee(p, call.expression, scope)?.kind === "auth") return true;
  return IDENTITY_CALLEE.test(calleePath(call.expression));
}

/** `supabase.auth.getUser()`, `getSession()`, `getClaims()`, or a call to an auth helper of this repository. */
function callsSession(
  p: Project,
  call: ts.CallExpression,
  sf: ts.SourceFile,
  scope: Map<string, Sym>,
): boolean {
  return (
    /\.auth\.(getUser|getSession|getClaims)$/.test(call.expression.getText(sf)) ||
    symOfCallee(p, call.expression, scope)?.kind === "auth"
  );
}

/**
 * The caller's identity an expression reads (`user.id`, `dev.id`, `advertiser`): null for the session
 * itself, the table of a row the identity selected, "" for a part of such a row; undefined for
 * anything else. User input never counts, and neither does `user_metadata`, which the user edits.
 * Evidence only: a helper merely named like authentication does not make its result an identity.
 */
function identityOf(frame: Frame, e: ts.Expression): string | null | undefined {
  if (frame.identities.size === 0 || derivedIn(frame, e)) return undefined;
  let u = unwrap(e);
  let part = false;
  while (ts.isPropertyAccessExpression(u) || ts.isElementAccessExpression(u)) {
    if (ts.isPropertyAccessExpression(u) && u.name.text === "user_metadata") return undefined;
    u = unwrap(u.expression);
    part = true;
  }
  if (!ts.isIdentifier(u) || !frame.identities.has(u.text)) return undefined;
  const who = frame.identities.get(u.text) ?? null;
  return part && who !== null ? "" : who;
}

/** Names that receive a result: `dev` of `{ data: dev }`, `user` of `{ data: { user } }`, a plain name; never `error`. */
function identityNamesOf(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  if (ts.isArrayBindingPattern(name)) {
    const first = name.elements[0];
    return first && !ts.isOmittedExpression(first) ? boundNames(first.name) : [];
  }
  const data = name.elements.find((el) => propertyKeyOf(el.propertyName ?? el.name) === "data");
  if (data) return boundNames(data.name);
  return name.elements
    .filter((el) => propertyKeyOf(el.propertyName ?? el.name) !== "error")
    .flatMap((el) => boundNames(el.name));
}

/**
 * A Supabase query whose row is the caller's: filtered with `eq`/`match` by the caller's identity
 * (`claimed_by = user.id`), or by a credential column with a value the caller sent (`token = <cookie>`,
 * the lookup that authenticates them). Its table; undefined otherwise.
 */
function identityRowOf(frame: Frame, call: ts.CallExpression): string | undefined {
  const { segments } = flattenChain(call);
  const table = stringLiteralValue(segments.find((s) => s.name === "from")?.args[0]);
  if (table === null) return undefined;
  const keyed = (column: string | null, value: ts.Expression | undefined): boolean =>
    value !== undefined &&
    (identityOf(frame, value) !== undefined ||
      (isCredentialColumn(column) && derivedIn(frame, value)));
  for (const s of segments) {
    if (s.name === "eq" && keyed(stringLiteralValue(s.args[0]), s.args[1])) return table;
    const obj = s.name === "match" ? s.args[0] : undefined;
    if (!obj || !ts.isObjectLiteralExpression(obj)) continue;
    for (const pr of obj.properties) {
      if (ts.isPropertyAssignment(pr) && keyed(propertyKeyOf(pr.name), pr.initializer))
        return table;
    }
  }
  return undefined;
}

/** The identity a declaration or an assignment receives: every non-literal branch must be one. */
function identityBinding(
  p: Project,
  frame: Frame,
  init: ts.Expression,
  scope: Map<string, Sym>,
): string | null | undefined {
  let out: string | null | undefined;
  for (const leaf of branchesOf(init)) {
    if (isLiteralValue(leaf)) continue;
    const who = identityLeaf(p, frame, leaf, scope);
    if (who === undefined) return undefined;
    if (out === undefined) out = who;
  }
  return out;
}

function identityLeaf(
  p: Project,
  frame: Frame,
  leaf: ts.Expression,
  scope: Map<string, Sym>,
): string | null | undefined {
  const u = unwrap(leaf);
  if (ts.isPropertyAccessExpression(u) || ts.isElementAccessExpression(u)) {
    // `(await supabase.auth.getUser()).data.user`: a part of an identity a call returns.
    let base: ts.Expression = u;
    while (ts.isPropertyAccessExpression(base) || ts.isElementAccessExpression(base)) {
      if (ts.isPropertyAccessExpression(base) && base.name.text === "user_metadata")
        return undefined;
      base = unwrap(base.expression);
    }
    if (!ts.isCallExpression(base)) return identityOf(frame, u);
    if (derivedIn(frame, u)) return undefined;
    const who = identityLeaf(p, frame, base, scope);
    return who === undefined || who === null ? who : "";
  }
  if (ts.isIdentifier(u)) return identityOf(frame, u);
  if (!ts.isCallExpression(u)) return undefined;
  if (callsSession(p, u, frame.sf, scope)) return null;
  if (isChainWithQuery(u)) return identityRowOf(frame, u);
  if (isDbChain(u, frame)) return undefined;
  return returnIdentity(p, u, frame, scope);
}

/**
 * The identity a helper of this repository returns (see identityOf), evaluated in its own frame with
 * the caller's arguments bound. Undefined when some path returns anything else, or when the callee is
 * not a function of this repository. Literal returns (`return null` when signed out) do not count
 * against it.
 */
function returnIdentity(
  p: Project,
  call: ts.CallExpression,
  frame: Frame,
  scope: Map<string, Sym>,
): string | null | undefined {
  if (frame.depth >= MAX_DEPTH) return undefined;
  const target = callTarget(p, call, frame, scope);
  if (!target) return undefined;
  const child = childFrame(p, call, target, frame);
  if (!child) return undefined;
  const key = `${target.facts.file}#${target.name}#${frameSignature(child)}`;
  const cached = p.returnIdentities.get(key);
  if (cached !== undefined) return cached === false ? undefined : cached.who;
  // A helper that (indirectly) calls itself returns no identity.
  p.returnIdentities.set(key, false);
  bindDeclarations(p, child, {
    inputs: [],
    authChecks: [],
    roleChecks: [],
    queries: [],
    metadataAccesses: [],
    visited: new Set(),
    reads: [],
  });
  const childScope = scopeOf(p, child.facts);
  let out: { who: string | null } | false = false;
  for (const ret of ownReturns(target.fn)) {
    for (const leaf of branchesOf(ret)) {
      if (isLiteralValue(leaf)) continue;
      const who = identityLeaf(p, child, leaf, childScope);
      if (who === undefined) return undefined;
      if (out === false) out = { who };
    }
  }
  p.returnIdentities.set(key, out);
  return out === false ? undefined : out.who;
}

/**
 * The names a callee is made of, without call arguments: `request.headers.get()?.slice` for
 * `request.headers.get("authorization")?.slice`, so a string argument never reads as a name.
 */
function calleePath(e: ts.Expression): string {
  const u = unwrap(e);
  if (ts.isIdentifier(u)) return u.text;
  if (ts.isPropertyAccessExpression(u)) return `${calleePath(u.expression)}.${u.name.text}`;
  if (ts.isCallExpression(u)) return `${calleePath(u.expression)}()`;
  if (ts.isElementAccessExpression(u)) return `${calleePath(u.expression)}[]`;
  return "";
}

// ---------------------------------------------------------------------------------------------
// Handlers.

interface HandlerInput {
  rel: string;
  sf: ts.SourceFile;
  facts: ModuleFacts;
  kind: EntryKind;
  route: string;
  method: HttpMethod | "ACTION" | "PAGE";
  fn: FunctionLike;
  node: ts.Node;
  wrapper: string | undefined;
}

interface LayoutGuards {
  authChecks: AuthCheck[];
  roleChecks: RoleCheck[];
}

const EMPTY_GUARDS: LayoutGuards = { authChecks: [], roleChecks: [] };

/**
 * Auth evidence of the `layout.tsx` files above a page. In the App Router every ancestor layout
 * renders before the page, so a layout that reads the session and redirects (or 404s) without one
 * guards everything below it: `app/admin/layout.tsx` calling `requireReviewer()` then `notFound()`
 * authenticates every admin page. Only the auth evidence is taken; the layout's own queries stay
 * with the layout.
 */
function layoutGuards(p: Project, pageRel: string, cache: Map<string, LayoutGuards>): LayoutGuards {
  const parts = pageRel.split("/");
  parts.pop();
  const out: LayoutGuards = { authChecks: [], roleChecks: [] };
  for (let i = parts.length; i > 0; i--) {
    const g = layoutGuardsFor(p, parts.slice(0, i).join("/"), cache);
    out.authChecks.push(...g.authChecks);
    out.roleChecks.push(...g.roleChecks);
  }
  return out;
}

const LAYOUT_EXTENSIONS = ["tsx", "ts", "jsx", "js"] as const;

function layoutGuardsFor(p: Project, dir: string, cache: Map<string, LayoutGuards>): LayoutGuards {
  const hit = cache.get(dir);
  if (hit) return hit;
  let guards = EMPTY_GUARDS;
  for (const ext of LAYOUT_EXTENSIONS) {
    const rel = `${dir}/layout.${ext}`;
    const sf = p.sources.get(rel);
    const facts = p.registry.get(rel);
    if (!sf || !facts || isClientComponentFile(sf)) continue;
    const fn = pageHandlerIn(sf);
    if (!fn) continue;
    try {
      const analysed = analyzeHandler(p, {
        rel,
        sf,
        facts,
        kind: "page",
        route: dir,
        method: "PAGE",
        fn: fn.fn,
        node: fn.node,
        wrapper: fn.wrapper,
      });
      guards = { authChecks: analysed.authChecks, roleChecks: analysed.roleChecks ?? [] };
    } catch {
      // A layout the analyser cannot read guards nothing, exactly like no layout at all.
      guards = EMPTY_GUARDS;
    }
    break;
  }
  cache.set(dir, guards);
  return guards;
}

function analyzeHandler(p: Project, h: HandlerInput): RouteHandler {
  const { rel, sf, fn } = h;
  const loc = (n: ts.Node): FileRef => ({ file: rel, line: lineOf(sf, n) });
  const acc: Acc = {
    inputs: [],
    authChecks: [],
    roleChecks: [],
    queries: [],
    metadataAccesses: [],
    visited: new Set(),
    reads: [],
  };
  const frame: Frame = {
    rel,
    sf,
    facts: h.facts,
    fn,
    depth: 0,
    via: [],
    inputNames: new Set(["params", "searchParams"]),
    // The implicit `params`/`searchParams` names are not whole objects: a callback parameter that
    // happens to be called `params` (an AI tool's arguments) is not the request.
    wholeNames: new Set(),
    partialInputs: new Map(),
    reqNames: new Set(),
    clients: new Map(),
    instances: new Map(),
    cls: null,
    thisProps: new Map(),
    key: "h",
    aliases: new Map(),
    pathPos: [],
    exitPropagates: true,
    identities: new Map(),
  };
  const first = fn.parameters[0];
  if (h.kind === "route" && first) {
    if (ts.isIdentifier(first.name)) frame.reqNames.add(first.name.text);
    else for (const nm of boundNames(first.name)) if (REQUEST_NAME.test(nm)) frame.reqNames.add(nm);
  }
  if (h.kind === "server_action") {
    // Every argument of a plain server action is attacker-controlled: the client sends them.
    // A wrapped action receives the validated payload first and wrapper-provided context after.
    const params = h.wrapper ? fn.parameters.slice(0, 1) : fn.parameters;
    for (const prm of params) {
      for (const nm of boundNames(prm.name)) {
        if (!acc.inputs.some((i) => i.kind === "action_arg" && i.name === nm)) {
          acc.inputs.push({ kind: "action_arg", name: nm, location: loc(prm) });
        }
        frame.inputNames.add(nm);
        frame.wholeNames.add(nm);
      }
    }
  }
  if (h.wrapper && WRAPPER_AUTH.test(h.wrapper)) {
    acc.authChecks.push({ ...loc(h.node), kind: "session" });
  }
  analyzeFrame(p, frame, acc);
  linkGuards(acc.reads, p.tables);

  const entry =
    h.kind === "route"
      ? `${h.method} ${h.route}`
      : h.kind === "page"
        ? `PAGE ${h.route}`
        : `server action ${h.route}`;
  const stmt = enclosingStatement(h.node);
  const ignores: IgnoreDirective[] = parseIgnoreDirectives(sf, stmt.getFullStart()).map((d) => ({
    ruleId: d.ruleId,
    reason: d.reason,
    location: { file: rel, line: d.line },
  }));
  return {
    kind: h.kind,
    route: h.route,
    method: h.method,
    entry,
    location: loc(h.node),
    inputs: acc.inputs,
    authChecks: acc.authChecks,
    queries: acc.queries,
    metadataAccesses: acc.metadataAccesses,
    ignores,
    roleChecks: acc.roleChecks,
  };
}

/** `process.env.NEXT_PUBLIC_…SECRET…` and `process.env["NEXT_PUBLIC_…"]` reads, in source order. */
function publicSecretEnvReads(sf: ts.SourceFile): Array<{ name: string; node: ts.Node }> {
  const isProcessEnv = (e: ts.Expression): boolean =>
    ts.isPropertyAccessExpression(e) &&
    e.name.text === "env" &&
    ts.isIdentifier(e.expression) &&
    e.expression.text === "process";
  const out: Array<{ name: string; node: ts.Node }> = [];
  const visit = (n: ts.Node): void => {
    if (ts.isPropertyAccessExpression(n) && isProcessEnv(n.expression)) {
      if (PUBLIC_SECRET_ENV.test(n.name.text)) out.push({ name: n.name.text, node: n });
    } else if (
      ts.isElementAccessExpression(n) &&
      isProcessEnv(n.expression) &&
      ts.isStringLiteralLike(n.argumentExpression) &&
      PUBLIC_SECRET_ENV.test(n.argumentExpression.text)
    ) {
      out.push({ name: n.argumentExpression.text, node: n });
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return out;
}

function findExposures(rel: string, sf: ts.SourceFile): SecretExposure[] {
  const out: SecretExposure[] = [];
  // Only real reads count: Next.js inlines `process.env.NEXT_PUBLIC_X` member expressions, not the same
  // text inside a string, a template or a comment (documentation pages quote the vulnerable line).
  for (const name of publicSecretEnvReads(sf)) {
    out.push({
      kind: "public_env_service_role",
      location: { file: rel, line: lineOf(sf, name.node) },
      evidence: `process.env.${name.name} is inlined into the browser bundle by Next.js because of the NEXT_PUBLIC_ prefix`,
    });
  }
  if (isClientComponentFile(sf)) {
    for (const call of collect(sf, ts.isCallExpression)) {
      if (!isCreateClientCall(call, sf)) continue;
      const c = classifyCreateClientCall(call, sf);
      if (c.kind === "service_role") {
        out.push({
          kind: "service_role_in_client_component",
          location: { file: rel, line: lineOf(sf, call) },
          evidence: `"use client" file creates a Supabase client with a service-role key: ${c.evidence}`,
        });
      }
    }
  }
  // One root cause, one finding: a client component that builds a service-role client already covers
  // the NEXT_PUBLIC_ variable it reads, so drop the env-name exposures for that file.
  if (out.some((x) => x.kind === "service_role_in_client_component")) {
    return out.filter((x) => x.kind !== "public_env_service_role");
  }
  return out;
}

/** Parses a Next.js + Supabase project directory into a ProjectModel. Never throws on malformed input. */
export function parseProject(rootInput: string, opts: ParseOptions = {}): ProjectModel {
  const root = resolve(rootInput);
  const discovered = discoverFiles(root, opts.sqlDirs ?? [], opts.ignore ?? []);
  const { source, sql, manifests, tsconfigs, prisma } = discovered;
  // Rejected ignore globs and unreadable directories belong in the model, not only in runScan.
  const warnings: string[] = [...discovered.warnings];
  const sources = new Map<string, ts.SourceFile>();
  for (const rel of source) {
    try {
      sources.set(rel, parseSource(rel, readFileSync(join(root, rel), "utf8")));
    } catch (e) {
      warnings.push(`could not read ${rel}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  const registry = new Map<string, ModuleFacts>();
  for (const [rel, sf] of sources) {
    try {
      registry.set(rel, analyzeModule(rel, sf));
    } catch (e) {
      // A file the walker cannot handle (pathological nesting, a construct that trips a visitor) is
      // dropped from the model with a warning; the rest of the project is still scanned.
      sources.delete(rel);
      warnings.push(`could not analyse ${rel}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  const tables = new Map<string, RlsTable>();
  for (const rel of appliedSqlFiles(sql)) {
    try {
      parseSqlForRls(rel, readFileSync(resolve(root, rel), "utf8"), tables);
    } catch (e) {
      warnings.push(`could not read ${rel}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  const prismaModels = new Map<string, string>();
  for (const rel of prisma) {
    try {
      for (const [k, v] of parsePrismaSchema(readFileSync(join(root, rel), "utf8"))) {
        prismaModels.set(k, v);
      }
    } catch (e) {
      warnings.push(`could not read ${rel}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  const drizzleTablesByExport = new Map<string, string>();
  for (const f of registry.values()) {
    for (const [k, v] of f.drizzleTables) drizzleTablesByExport.set(k, v);
  }
  const project: Project = {
    sources,
    registry,
    resolver: new Resolver(root, new Set(source), manifests, tsconfigs, warnings),
    scopes: new Map(),
    factoryOfFn: new Map(),
    varBindings: new Map(),
    drizzleTablesByExport,
    prismaModels,
    returnTaints: new Map(),
    returnIdentities: new Map(),
    tables,
    warnings,
  };

  const routes: RouteHandler[] = [];
  const exposures: SecretExposure[] = [];
  const fileIgnores: Record<string, IgnoreDirective[]> = {};
  for (const [rel, sf] of sources) {
    try {
      analyzeFile(project, rel, sf, registry.get(rel) ?? analyzeModule(rel, sf), {
        routes,
        exposures,
        fileIgnores,
      });
    } catch (e) {
      // Handlers of this file analysed before the failure stay; the rest of the file is skipped.
      warnings.push(`could not analyse ${rel}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  routes.sort((a, b) => a.entry.localeCompare(b.entry));

  const all = [...registry.values()];
  const schema = sqlSchemaFor(tables);
  warnings.push(...schema.warnings);
  return {
    root,
    files: [...source, ...sql],
    routes,
    clientFactories: all.flatMap((f) => f.clientFactories),
    authHelpers: all.flatMap((f) => f.authHelpers),
    tables: [...tables.values()],
    exposures,
    fileIgnores,
    warnings,
    enums: schema.enums,
    sqlFunctions: schema.sqlFunctions,
    storageBuckets: schema.storageBuckets,
    ...(schema.triggers.length > 0 ? { sqlTriggers: schema.triggers } : {}),
  };
}

interface FileOutputs {
  routes: RouteHandler[];
  exposures: SecretExposure[];
  fileIgnores: Record<string, IgnoreDirective[]>;
}

/** Layout guards already computed for this project, by directory. Cleared with the project. */
const LAYOUT_CACHE = new WeakMap<Project, Map<string, LayoutGuards>>();

function layoutCacheOf(p: Project): Map<string, LayoutGuards> {
  let m = LAYOUT_CACHE.get(p);
  if (!m) {
    m = new Map();
    LAYOUT_CACHE.set(p, m);
  }
  return m;
}

/** Everything one source file contributes: file-level directives, secret exposures and its entry points. */
function analyzeFile(
  project: Project,
  rel: string,
  sf: ts.SourceFile,
  facts: ModuleFacts,
  out: FileOutputs,
): void {
  const { routes, exposures, fileIgnores } = out;
  {
    const top = parseIgnoreDirectives(sf, 0).map((d) => ({
      ruleId: d.ruleId,
      reason: d.reason,
      location: { file: rel, line: d.line },
    }));
    if (top.length > 0) fileIgnores[rel] = top;
    exposures.push(...findExposures(rel, sf));
    const route = routeFromFile(rel);
    if (route) {
      for (const { method, exported } of routeHandlersIn(sf)) {
        routes.push(
          analyzeHandler(project, {
            rel,
            sf,
            facts,
            kind: "route",
            route,
            method,
            fn: exported.fn,
            node: exported.node,
            wrapper: exported.wrapper,
          }),
        );
      }
    } else if (isServerActionFile(sf)) {
      for (const ex of exportedFunctions(sf)) {
        routes.push(
          analyzeHandler(project, {
            rel,
            sf,
            facts,
            kind: "server_action",
            route: ex.name,
            method: "ACTION",
            fn: ex.fn,
            node: ex.node,
            wrapper: ex.wrapper,
          }),
        );
      }
    } else {
      // A server-rendered page is a GET whose inputs are its params and searchParams.
      const page = pageFromFile(rel);
      const handler = page !== null && !isClientComponentFile(sf) ? pageHandlerIn(sf) : null;
      if (page !== null && handler) {
        const analysed = analyzeHandler(project, {
          rel,
          sf,
          facts,
          kind: "page",
          route: page,
          method: "PAGE",
          fn: handler.fn,
          node: handler.node,
          wrapper: handler.wrapper,
        });
        const guards = layoutGuards(project, rel, layoutCacheOf(project));
        analysed.authChecks.push(...guards.authChecks);
        if (guards.roleChecks.length > 0) {
          analysed.roleChecks = [...(analysed.roleChecks ?? []), ...guards.roleChecks];
        }
        // A page that reads nothing and takes no input is not an entry point worth reporting on.
        if (analysed.queries.length > 0 || analysed.inputs.length > 0) routes.push(analysed);
      }
    }
  }
}
