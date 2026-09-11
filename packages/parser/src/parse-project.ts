import { readFileSync } from "node:fs";
import { join, posix, resolve } from "node:path";
import ts from "typescript";
import {
  boundNames,
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
  appRootOf,
  isClientComponentFile,
  isServerActionFile,
  routeFromFile,
  routeHandlersIn,
} from "./nextjs.js";
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

interface ClientBinding {
  kind: ClientKind;
  name: string;
  location: FileRef;
}

interface HandlerContext {
  rel: string;
  sf: ts.SourceFile;
  kind: EntryKind;
  route: string;
  method: HttpMethod | "ACTION";
  fn: FunctionLike;
  node: ts.Node;
  facts: ModuleFacts;
  registry: Map<string, ModuleFacts>;
  files: Set<string>;
  warnings: string[];
}

export interface ParseOptions {
  /** Extra directories to scan for migration SQL, absolute or relative to the project root. */
  sqlDirs?: readonly string[];
  /** Glob patterns (relative to root) to leave out of the scan, e.g. intentionally vulnerable fixtures. */
  ignore?: readonly string[];
}

function resolveImport(spec: string, fromRel: string, files: Set<string>): string | null {
  let base: string;
  const bases: string[] = [];
  if (spec.startsWith("@/") || spec.startsWith("~/")) {
    base = spec.slice(2);
    // `@/` points at the app's own root (apps/web/ in a monorepo), then at the repository root as a fallback.
    const appRoot = appRootOf(fromRel);
    if (appRoot) bases.push(posix.join(appRoot, base), posix.join(appRoot, "src", base));
    bases.push(base, `src/${base}`);
  } else if (spec.startsWith(".")) {
    base = posix.normalize(posix.join(posix.dirname(fromRel), spec));
    bases.push(base);
  } else return null;
  for (const b of bases) {
    for (const c of [
      `${b}.ts`,
      `${b}.tsx`,
      `${b}.js`,
      `${b}.jsx`,
      `${b}/index.ts`,
      `${b}/index.tsx`,
      b,
    ]) {
      if (files.has(c)) return c;
    }
  }
  return null;
}

function analyzeHandler(ctx: HandlerContext): RouteHandler {
  const { rel, sf, fn, facts, registry, files } = ctx;
  const loc = (n: ts.Node): FileRef => ({ file: rel, line: lineOf(sf, n) });

  // Helpers visible in this handler: imported factories/auth helpers plus same-file ones.
  const factories = new Map<string, ClientFactory>();
  const authHelpers = new Map<string, AuthHelper>();
  for (const [local, spec] of facts.imports) {
    const target = resolveImport(spec, rel, files);
    const tf = target ? registry.get(target) : undefined;
    if (tf) {
      const cf = tf.clientFactories.find((c) => c.name === local);
      if (cf) factories.set(local, cf);
      const ah = tf.authHelpers.find((a) => a.name === local);
      if (ah) authHelpers.set(local, ah);
    } else if (spec.startsWith(".") || spec.startsWith("@/") || spec.startsWith("~/")) {
      let matched = false;
      for (const f of registry.values()) {
        const cf = f.clientFactories.find((c) => c.name === local);
        if (cf) {
          factories.set(local, cf);
          matched = true;
        }
        const ah = f.authHelpers.find((a) => a.name === local);
        if (ah) {
          authHelpers.set(local, ah);
          matched = true;
        }
      }
      if (matched)
        ctx.warnings.push(`unresolved import "${spec}" in ${rel}; matched "${local}" by name`);
    }
  }
  for (const cf of facts.clientFactories) factories.set(cf.name, cf);
  for (const ah of facts.authHelpers) authHelpers.set(ah.name, ah);

  const body: ts.Node = fn.body ?? fn;
  const firstParam = fn.parameters[0];
  const reqName = firstParam && ts.isIdentifier(firstParam.name) ? firstParam.name.text : null;

  // User-controlled inputs.
  const inputs: InputSource[] = [];
  const inputNames = new Set<string>(["params", "searchParams"]);
  const addInput = (kind: InputKind, name: string, n: ts.Node, bind: boolean): void => {
    if (!inputs.some((i) => i.kind === kind && i.name === name))
      inputs.push({ kind, name, location: loc(n) });
    if (bind) inputNames.add(name);
  };
  if (ctx.kind === "server_action") {
    // Every argument of a server action is attacker-controlled: the client sends them.
    for (const p of fn.parameters)
      for (const nm of boundNames(p.name)) addInput("action_arg", nm, p, true);
  }
  walk(body, (n) => {
    if (ts.isVariableDeclaration(n) && n.initializer) {
      const init = unwrap(n.initializer);
      const text = init.getText(sf);
      if (/^(params|context\.params|ctx\.params|props\.params)$/.test(text)) {
        for (const nm of boundNames(n.name)) addInput("route_param", nm, n, true);
      } else if (
        ts.isCallExpression(init) &&
        /\.(json|formData|text)\(\)$/.test(text) &&
        (reqName ? text.startsWith(`${reqName}.`) : /^(req|request)\./.test(text))
      ) {
        for (const nm of boundNames(n.name)) addInput("body", nm, n, true);
      } else if (/searchParams\.get\(|\.searchParams$|^new URL\(/.test(text)) {
        for (const nm of boundNames(n.name)) addInput("query", nm, n, true);
      } else if (/headers\.get\(/.test(text)) {
        for (const nm of boundNames(n.name)) addInput("header", nm, n, true);
      } else if (ts.isIdentifier(init) && inputNames.has(init.text)) {
        // const payload = body; keeps the taint
        for (const nm of boundNames(n.name)) addInput("body", nm, n, true);
      }
    }
    if (
      ts.isPropertyAccessExpression(n) &&
      ts.isIdentifier(n.expression) &&
      n.expression.text === "params"
    ) {
      addInput("route_param", n.name.text, n, false);
    }
    return undefined;
  });
  const derived = (e: ts.Node): boolean => {
    for (const id of identifiersIn(e)) if (inputNames.has(id)) return true;
    return /^(params|body|query|searchParams)\b/.test(e.getText(sf));
  };
  const isWholeInput = (e: ts.Expression): boolean => {
    const u = unwrap(e);
    if (ts.isIdentifier(u)) return inputNames.has(u.text);
    if (ts.isObjectLiteralExpression(u)) {
      return u.properties.some(
        (p) =>
          ts.isSpreadAssignment(p) &&
          ts.isIdentifier(unwrap(p.expression)) &&
          inputNames.has((unwrap(p.expression) as ts.Identifier).text),
      );
    }
    return false;
  };

  // Client bindings and auth checks.
  const classifyClientCall = (call: ts.CallExpression): ClientBinding | null => {
    if (ts.isIdentifier(call.expression)) {
      const f = factories.get(call.expression.text);
      if (f) return { kind: f.kind, name: f.name, location: f.location };
    }
    if (isCreateClientCall(call, sf)) {
      const c = classifyCreateClientCall(call, sf);
      return { kind: c.kind, name: call.expression.getText(sf), location: loc(call) };
    }
    return null;
  };
  const clients = new Map<string, ClientBinding>();
  const authChecks: FileRef[] = [];
  for (const call of collect(body, ts.isCallExpression)) {
    const calleeText = call.expression.getText(sf);
    if (/\.auth\.(getUser|getSession|getClaims)$/.test(calleeText)) authChecks.push(loc(call));
    else if (ts.isIdentifier(call.expression) && authHelpers.has(call.expression.text))
      authChecks.push(loc(call));
  }
  for (const decl of collect(body, ts.isVariableDeclaration)) {
    if (!decl.initializer || !ts.isIdentifier(decl.name)) continue;
    const init = unwrap(decl.initializer);
    if (!ts.isCallExpression(init)) continue;
    const binding = classifyClientCall(init);
    if (binding) clients.set(decl.name.text, binding);
  }

  // Metadata accesses: user_metadata is end-user editable, app_metadata is not.
  const metadataAccesses: MetadataAccess[] = [];
  for (const pa of collect(body, ts.isPropertyAccessExpression)) {
    const inner = pa.expression;
    if (
      ts.isPropertyAccessExpression(inner) &&
      (inner.name.text === "user_metadata" || inner.name.text === "app_metadata")
    ) {
      metadataAccesses.push({ path: pa.getText(sf), bucket: inner.name.text, location: loc(pa) });
    }
  }

  // Supabase query chains.
  const queries: SupabaseQuery[] = [];
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

    let client: ClientKind = "unknown";
    let clientName: string | null = null;
    let clientLocation: FileRef | null = null;
    const root = unwrap(chain.root);
    let binding: ClientBinding | null = null;
    if (ts.isIdentifier(root)) {
      binding = clients.get(root.text) ?? null;
      if (!binding) clientName = root.text;
    } else if (ts.isCallExpression(root)) {
      binding = classifyClientCall(root);
    }
    if (binding) {
      client = binding.kind;
      clientName = binding.name;
      clientLocation = binding.location;
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
            inputDerived: derived(arg),
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
        for (const p of first.properties) {
          if (ts.isPropertyAssignment(p)) {
            filters.push({
              method: "match",
              column: p.name.getText(sf).replace(/['"]/g, ""),
              valueText: p.initializer.getText(sf),
              inputDerived: derived(p.initializer),
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
        inputDerived: val ? derived(val) : false,
      });
    }
    queries.push({
      table: stringLiteralValue(anchor.args[0]) ?? "(dynamic)",
      operation,
      client,
      clientName,
      clientLocation,
      filters,
      payload,
      location: loc(anchor.node),
      text: call.getText(sf).replace(/\s+/g, " ").slice(0, 200),
    });
  }

  const entry = ctx.kind === "route" ? `${ctx.method} ${ctx.route}` : `server action ${ctx.route}`;
  const stmt = enclosingStatement(ctx.node);
  const ignores: IgnoreDirective[] = parseIgnoreDirectives(sf, stmt.getFullStart()).map((d) => ({
    ruleId: d.ruleId,
    reason: d.reason,
    location: { file: rel, line: d.line },
  }));
  return {
    kind: ctx.kind,
    route: ctx.route,
    method: ctx.method,
    entry,
    location: loc(ctx.node),
    inputs,
    authChecks,
    queries,
    metadataAccesses,
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
  const { source, sql } = discoverFiles(root, opts.sqlDirs ?? [], opts.ignore ?? []);
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

  const files = new Set(source);
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
    const common = { rel, sf, facts, registry, files, warnings };
    const route = routeFromFile(rel);
    if (route) {
      for (const { method, exported } of routeHandlersIn(sf)) {
        routes.push(
          analyzeHandler({
            ...common,
            kind: "route",
            route,
            method,
            fn: exported.fn,
            node: exported.node,
          }),
        );
      }
    } else if (isServerActionFile(sf)) {
      for (const ex of exportedFunctions(sf)) {
        routes.push(
          analyzeHandler({
            ...common,
            kind: "server_action",
            route: ex.name,
            method: "ACTION",
            fn: ex.fn,
            node: ex.node,
          }),
        );
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
