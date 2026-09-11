import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import ts from "typescript";
import {
  boundNames,
  type ClassInfo,
  collect,
  enclosingStatement,
  exportedFunctions,
  type FunctionLike,
  flattenChain,
  identifiersIn,
  isChainTail,
  lineOf,
  parseIgnoreDirectives,
  parseSource,
  stringLiteralValue,
  unwrap,
  walk,
} from "./ast.js";
import { discoverFiles } from "./discover.js";
import type {
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
  QueryOperation,
  QueryPayload,
  RlsTable,
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
import { Resolver } from "./resolve.js";
import { parseSqlForRls } from "./rls.js";
import {
  analyzeModule,
  classifyCreateClientCall,
  isCreateClientCall,
  type ModuleFacts,
} from "./supabase.js";

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
const PUBLIC_SECRET_ENV = /process\.env\.NEXT_PUBLIC_[A-Z0-9_]*(?:SERVICE_ROLE|SECRET)[A-Z0-9_]*/g;
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
  isRequest: boolean;
}

const NO_ARG: ArgBinding = { client: null, instance: null, tainted: false, isRequest: false };

type Sym =
  | { kind: "factory"; factory: ClientFactory }
  | { kind: "auth"; helper: AuthHelper }
  | { kind: "function"; name: string; fn: FunctionLike; facts: ModuleFacts }
  | { kind: "class"; cls: ClassInfo; facts: ModuleFacts }
  | { kind: "var"; name: string; init: ts.Expression; facts: ModuleFacts }
  | { kind: "namespace"; facts: ModuleFacts };

interface Project {
  sources: Map<string, ts.SourceFile>;
  registry: Map<string, ModuleFacts>;
  resolver: Resolver;
  scopes: Map<string, Map<string, Sym>>;
  factoryOfFn: Map<string, ClientBinding | null>;
  varBindings: Map<string, ArgBinding>;
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
  /** Identifiers holding the incoming Request object. */
  reqNames: Set<string>;
  clients: Map<string, ClientBinding>;
  instances: Map<string, InstanceBinding>;
  cls: ClassInfo | null;
  thisProps: Map<string, ArgBinding>;
}

interface Acc {
  inputs: InputSource[];
  authChecks: FileRef[];
  queries: SupabaseQuery[];
  metadataAccesses: MetadataAccess[];
  visited: Set<string>;
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
  if (helper) return { kind: "auth", helper };
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
  _frame: Frame | null,
  depth: number,
): ClientBinding | null {
  const sym = symOfCallee(p, call.expression, scope);
  if (sym?.kind === "factory") {
    return { kind: sym.factory.kind, name: sym.factory.name, location: sym.factory.location };
  }
  if (sym?.kind === "function") {
    const b = factoryOfFunction(p, sym, depth);
    if (b) return b;
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
  const init = unwrap(sym.init);
  let out: ArgBinding = NO_ARG;
  if (ts.isCallExpression(init)) {
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
    out = { client, instance, tainted: false, isRequest: false };
  } else if (ts.isNewExpression(init) && ts.isIdentifier(init.expression)) {
    const cs = scope.get(init.expression.text);
    if (cs?.kind === "class") {
      out = {
        client: null,
        instance: { cls: cs.cls, facts: cs.facts, ctorArgs: [] },
        tainted: false,
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
  for (const id of identifiersIn(e)) if (frame.inputNames.has(id)) return true;
  // In the handler itself, `params.x` / `body.x` are user input even before we saw the binding.
  return frame.depth === 0 && /^(params|body|query|searchParams)\b/.test(e.getText(frame.sf));
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
  return { client, instance, tainted: derivedIn(frame, arg), isRequest };
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

function analyzeFrame(p: Project, frame: Frame, acc: Acc): void {
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

  // Declarations in source order: inputs, client bindings, service instances, taint propagation.
  for (const decl of collect(body, ts.isVariableDeclaration)) {
    if (!decl.initializer) continue;
    const init = unwrap(decl.initializer);
    const names = boundNames(decl.name);
    const text = init.getText(sf);
    if (frame.depth === 0) {
      if (/^(params|context\.params|ctx\.params|props\.params)$/.test(text)) {
        for (const nm of names) addInput("route_param", nm, decl, true);
        continue;
      }
      if (ts.isCallExpression(init) && isRequestCall(text)) {
        for (const nm of names) addInput("body", nm, decl, true);
        continue;
      }
      if (/searchParams\.get\(|\.searchParams$|^new URL\(/.test(text)) {
        for (const nm of names) addInput("query", nm, decl, true);
        continue;
      }
      if (/headers\.get\(/.test(text)) {
        for (const nm of names) addInput("header", nm, decl, true);
        continue;
      }
    }
    if (ts.isCallExpression(init)) {
      const client = classifyCall(p, init, sf, scope, frame, 0);
      if (client && ts.isIdentifier(decl.name)) {
        frame.clients.set(decl.name.text, client);
        continue;
      }
      const inst = instanceOfCall(p, init, frame, scope);
      if (inst && ts.isIdentifier(decl.name)) {
        frame.instances.set(decl.name.text, inst);
        continue;
      }
      if (isQueryChain(init)) continue;
      // What a helper returns from user input is user input (`const body = await parseBody(req)`),
      // unless the helper establishes identity (`const user = await getUserFromRequest(req)`).
      if (returnsIdentity(p, init, sf, scope)) continue;
      const args = init.arguments.map((a) => argBinding(p, a, frame));
      if (args.some((a) => a.tainted || a.isRequest)) {
        for (const nm of names) frame.inputNames.add(nm);
      }
    } else if (ts.isNewExpression(init) && ts.isIdentifier(init.expression)) {
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
        for (const nm of names) {
          if (frame.depth === 0) addInput("body", nm, decl, true);
          else frame.inputNames.add(nm);
        }
      }
    } else if (!isChainWithQuery(init) && derivedIn(frame, init)) {
      for (const nm of names) frame.inputNames.add(nm);
    }
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

  const isWholeInput = (e: ts.Expression): boolean => {
    const u = unwrap(e);
    if (ts.isIdentifier(u)) return frame.inputNames.has(u.text);
    if (ts.isObjectLiteralExpression(u)) {
      return u.properties.some(
        (pr) =>
          ts.isSpreadAssignment(pr) &&
          ts.isIdentifier(unwrap(pr.expression)) &&
          frame.inputNames.has((unwrap(pr.expression) as ts.Identifier).text),
      );
    }
    return false;
  };

  // Auth checks.
  for (const call of collect(body, ts.isCallExpression)) {
    const calleeText = call.expression.getText(sf);
    if (/\.auth\.(getUser|getSession|getClaims)$/.test(calleeText)) acc.authChecks.push(loc(call));
    else if (symOfCallee(p, call.expression, scope)?.kind === "auth")
      acc.authChecks.push(loc(call));
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
        location: loc(pa),
      });
    }
  }

  // Supabase query chains.
  const seen = new Set<number>();
  for (const call of collect(body, ts.isCallExpression)) {
    if (!isChainTail(call)) continue;
    const chain = flattenChain(call);
    const fromIdx = chain.segments.findIndex((s) => s.name === "from");
    const rpcIdx = chain.segments.findIndex((s) => s.name === "rpc");
    const anchorIdx = fromIdx >= 0 ? fromIdx : rpcIdx;
    const anchor = chain.segments[anchorIdx];
    if (anchorIdx < 0 || !anchor) continue;
    if (seen.has(anchor.node.pos)) continue;
    seen.add(anchor.node.pos);

    let binding: ClientBinding | null = null;
    let clientName: string | null = null;
    const root = unwrap(chain.root);
    if (ts.isIdentifier(root)) {
      binding = frame.clients.get(root.text) ?? null;
      if (!binding) clientName = root.text;
    } else if (ts.isCallExpression(root)) {
      binding = classifyCall(p, root, sf, scope, frame, 0);
      if (!binding) clientName = root.expression.getText(sf);
    } else if (
      ts.isPropertyAccessExpression(root) &&
      root.expression.kind === ts.SyntaxKind.ThisKeyword
    ) {
      binding = frame.thisProps.get(root.name.text)?.client ?? null;
      if (!binding) clientName = root.getText(sf);
    }

    const after = chain.segments.slice(anchorIdx + 1);
    let operation: QueryOperation = fromIdx >= 0 ? "unknown" : "rpc";
    let payload: QueryPayload | null = null;
    for (const s of after) {
      if (OPERATIONS.has(s.name as QueryOperation)) {
        operation = s.name as QueryOperation;
        const arg = s.args[0];
        if (WRITE_OPERATIONS.has(operation) && arg) {
          payload = {
            text: arg.getText(sf).replace(/\s+/g, " ").slice(0, 200),
            inputDerived: derivedIn(frame, arg),
            wholeInput: isWholeInput(arg),
          };
        }
        break;
      }
    }
    const filters: QueryFilter[] = [];
    for (const s of after) {
      if (!FILTER_METHODS.has(s.name)) continue;
      const first = s.args[0];
      if (s.name === "match" && first && ts.isObjectLiteralExpression(first)) {
        for (const pr of first.properties) {
          if (ts.isPropertyAssignment(pr)) {
            filters.push({
              method: "match",
              column: pr.name.getText(sf).replace(/['"]/g, ""),
              valueText: pr.initializer.getText(sf),
              inputDerived: derivedIn(frame, pr.initializer),
            });
          }
        }
        continue;
      }
      const val = s.args[1];
      filters.push({
        method: s.name,
        column: stringLiteralValue(first),
        valueText: val ? val.getText(sf) : "",
        inputDerived: val ? derivedIn(frame, val) : false,
      });
    }
    const query: SupabaseQuery = {
      table: stringLiteralValue(anchor.args[0]) ?? "(dynamic)",
      operation,
      client: binding?.kind ?? "unknown",
      clientName: binding?.name ?? clientName,
      clientLocation: binding?.location ?? null,
      filters,
      payload,
      location: loc(anchor.node),
      text: call.getText(sf).replace(/\s+/g, " ").slice(0, 200),
    };
    if (frame.via.length > 0) query.via = frame.via;
    acc.queries.push(query);
  }

  // Follow calls into helpers, services and methods of this repository.
  if (frame.depth >= MAX_DEPTH) return;
  for (const call of collect(body, ts.isCallExpression)) {
    const target = callTarget(p, call, frame, scope);
    if (!target) continue;
    const tsf = p.sources.get(target.facts.file);
    if (!tsf) continue;
    const child: Frame = {
      rel: target.facts.file,
      sf: tsf,
      facts: target.facts,
      fn: target.fn,
      depth: frame.depth + 1,
      via: [...frame.via, `${target.name} (${target.facts.file}:${lineOf(tsf, target.fn)})`],
      inputNames: new Set(),
      reqNames: new Set(),
      clients: new Map(),
      instances: new Map(),
      cls: target.cls,
      thisProps: target.thisProps,
    };
    target.fn.parameters.forEach((param, i) => {
      const ab = argBinding(p, call.arguments[i], frame);
      const names = boundNames(param.name);
      const head = names[0];
      if (ab.client && head !== undefined && ts.isIdentifier(param.name)) {
        child.clients.set(head, ab.client);
      }
      if (ab.instance && head !== undefined && ts.isIdentifier(param.name)) {
        child.instances.set(head, ab.instance);
      }
      for (const nm of names) {
        if (ab.isRequest) child.reqNames.add(nm);
        if (ab.tainted) child.inputNames.add(nm);
      }
    });
    // Same helper, same bindings: analysed once per handler.
    const signature = [
      ...[...child.clients].map(([n, c]) => `${n}=${c.kind}`),
      ...[...child.inputNames].map((n) => `${n}!`),
      ...[...child.reqNames].map((n) => `${n}?`),
      ...[...child.thisProps].map(([n, b]) => `this.${n}=${b.client?.kind ?? "-"}`),
    ].sort();
    const key = `${target.facts.file}#${target.name}#${signature.join(",")}`;
    if (acc.visited.has(key)) continue;
    acc.visited.add(key);
    analyzeFrame(p, child, acc);
  }
}

function isChainWithQuery(e: ts.Expression): boolean {
  return ts.isCallExpression(e) && isQueryChain(e);
}

const IDENTITY_CALLEE = /\.auth\.|user|session|claims|auth|principal|viewer/i;

/** Calls that resolve who the caller is: their result is trusted identity, not attacker input. */
function returnsIdentity(
  p: Project,
  call: ts.CallExpression,
  sf: ts.SourceFile,
  scope: Map<string, Sym>,
): boolean {
  if (symOfCallee(p, call.expression, scope)?.kind === "auth") return true;
  return IDENTITY_CALLEE.test(call.expression.getText(sf));
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

function analyzeHandler(p: Project, h: HandlerInput): RouteHandler {
  const { rel, sf, fn } = h;
  const loc = (n: ts.Node): FileRef => ({ file: rel, line: lineOf(sf, n) });
  const acc: Acc = {
    inputs: [],
    authChecks: [],
    queries: [],
    metadataAccesses: [],
    visited: new Set(),
  };
  const frame: Frame = {
    rel,
    sf,
    facts: h.facts,
    fn,
    depth: 0,
    via: [],
    inputNames: new Set(["params", "searchParams"]),
    reqNames: new Set(),
    clients: new Map(),
    instances: new Map(),
    cls: null,
    thisProps: new Map(),
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
      }
    }
  }
  if (h.wrapper && WRAPPER_AUTH.test(h.wrapper)) acc.authChecks.push(loc(h.node));
  analyzeFrame(p, frame, acc);

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
  };
}

function findExposures(rel: string, sf: ts.SourceFile): SecretExposure[] {
  const out: SecretExposure[] = [];
  const text = sf.text;
  for (const m of text.matchAll(PUBLIC_SECRET_ENV)) {
    const line = sf.getLineAndCharacterOfPosition(m.index ?? 0).line + 1;
    out.push({
      kind: "public_env_service_role",
      location: { file: rel, line },
      evidence: `${m[0]} is inlined into the browser bundle by Next.js because of the NEXT_PUBLIC_ prefix`,
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
  const { source, sql, manifests, tsconfigs } = discoverFiles(
    root,
    opts.sqlDirs ?? [],
    opts.ignore ?? [],
  );
  const warnings: string[] = [];
  const sources = new Map<string, ts.SourceFile>();
  for (const rel of source) {
    try {
      sources.set(rel, parseSource(rel, readFileSync(join(root, rel), "utf8")));
    } catch (e) {
      warnings.push(`could not read ${rel}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  const registry = new Map<string, ModuleFacts>();
  for (const [rel, sf] of sources) registry.set(rel, analyzeModule(rel, sf));

  const tables = new Map<string, RlsTable>();
  for (const rel of sql) {
    try {
      parseSqlForRls(rel, readFileSync(resolve(root, rel), "utf8"), tables);
    } catch (e) {
      warnings.push(`could not read ${rel}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  const project: Project = {
    sources,
    registry,
    resolver: new Resolver(root, new Set(source), manifests, tsconfigs, warnings),
    scopes: new Map(),
    factoryOfFn: new Map(),
    varBindings: new Map(),
    warnings,
  };

  const routes: RouteHandler[] = [];
  const exposures: SecretExposure[] = [];
  const fileIgnores: Record<string, IgnoreDirective[]> = {};
  for (const [rel, sf] of sources) {
    const top = parseIgnoreDirectives(sf, 0).map((d) => ({
      ruleId: d.ruleId,
      reason: d.reason,
      location: { file: rel, line: d.line },
    }));
    if (top.length > 0) fileIgnores[rel] = top;
    exposures.push(...findExposures(rel, sf));
    const facts = registry.get(rel) ?? analyzeModule(rel, sf);
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
        // A page that reads nothing and takes no input is not an entry point worth reporting on.
        if (analysed.queries.length > 0 || analysed.inputs.length > 0) routes.push(analysed);
      }
    }
  }
  routes.sort((a, b) => a.entry.localeCompare(b.entry));

  const all = [...registry.values()];
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
  };
}
