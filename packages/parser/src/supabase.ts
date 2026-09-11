import ts from "typescript";
import {
  type ClassInfo,
  classesIn,
  collect,
  lineOf,
  type TopLevelFunction,
  topLevelFunctions,
  unwrap,
} from "./ast.js";
import type { AuthHelper, ClientFactory, ClientKind } from "./model.js";

export const CREATE_CLIENT_CALLEES = /^(createClient|createServerClient|createBrowserClient)$/;

export function isCreateClientCall(call: ts.CallExpression, sf: ts.SourceFile): boolean {
  const callee = call.expression;
  if (ts.isIdentifier(callee)) return CREATE_CLIENT_CALLEES.test(callee.text);
  if (ts.isPropertyAccessExpression(callee)) return CREATE_CLIENT_CALLEES.test(callee.name.text);
  return CREATE_CLIENT_CALLEES.test(callee.getText(sf));
}

/**
 * Text of an argument, with identifiers resolved to their nearest declaration so that
 * `const key = process.env.SUPABASE_SERVICE_ROLE_KEY; createClient(url, key)` is still recognised.
 */
export function resolveArgText(expr: ts.Expression, sf: ts.SourceFile): string {
  const u = unwrap(expr);
  if (!ts.isIdentifier(u)) return expr.getText(sf);
  let scope: ts.Node | undefined = expr.parent;
  while (scope) {
    if (ts.isFunctionLike(scope) || ts.isBlock(scope) || ts.isSourceFile(scope)) {
      const decl = collect(scope, ts.isVariableDeclaration).find(
        (d) => ts.isIdentifier(d.name) && d.name.text === u.text && d.initializer,
      );
      if (decl?.initializer) return `${u.text} = ${decl.initializer.getText(sf)}`;
    }
    scope = scope.parent;
  }
  return expr.getText(sf);
}

/** Decides which Postgres role a client will act as, from the key argument and options. */
export function classifyCreateClientCall(
  call: ts.CallExpression,
  sf: ts.SourceFile,
): { kind: ClientKind; evidence: string } {
  const callee = call.expression.getText(sf);
  const args = call.arguments.map((a) => resolveArgText(a, sf));
  const keyArg = args[1] ?? "";
  const optArg = args[2] ?? "";
  if (/createServerClient|createBrowserClient/.test(callee)) {
    return {
      kind: "user_scoped",
      evidence: `${callee}() from @supabase/ssr acts as the signed-in user; RLS applies`,
    };
  }
  // SERVICE_ROLE_KEY, serviceRoleKey, getServiceRoleKey(), sb_secret_… all name the secret key.
  if (/SERVICE_?ROLE|SECRET_KEY|SB_SECRET/i.test(keyArg)) {
    return {
      kind: "service_role",
      evidence: `key ${keyArg} is a service-role secret; RLS is bypassed`,
    };
  }
  const anonKey = /ANON|PUBLISHABLE/i.test(keyArg);
  if (anonKey && /Authorization|headers/i.test(optArg)) {
    return {
      kind: "user_scoped",
      evidence: "anon key with a per-request Authorization header; RLS applies as the caller",
    };
  }
  if (anonKey) {
    return {
      kind: "anon",
      evidence: "anon key without a user token; RLS applies as the anonymous role",
    };
  }
  return { kind: "unknown", evidence: `could not classify key argument ${keyArg || "(none)"}` };
}

const AUTH_CALL = /\.auth\.(getUser|getSession|getClaims)\s*\(/;

export interface ImportRef {
  spec: string;
  /** Exported name in the target module, `default`, or `*` for a namespace import. */
  imported: string;
}

export interface ModuleVar {
  name: string;
  init: ts.Expression;
  exported: boolean;
  node: ts.VariableDeclaration;
}

export type Reexport =
  | { star: true; spec: string }
  | { star: false; name: string; alias: string; spec: string };

export interface ModuleFacts {
  file: string;
  clientFactories: ClientFactory[];
  authHelpers: AuthHelper[];
  /** local name -> what was imported and from where */
  imports: Map<string, ImportRef>;
  /** Every top-level function, exported or not. */
  functions: Map<string, TopLevelFunction>;
  classes: Map<string, ClassInfo>;
  /** Top-level `const x = <call or new>` declarations: module-level clients and service instances. */
  moduleVars: Map<string, ModuleVar>;
  reexports: Reexport[];
  /** Local name behind `export default`, when it is a named function or identifier. */
  defaultExport: string | null;
}

function hasModifier(node: ts.Node, kind: ts.SyntaxKind): boolean {
  const mods = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
  return mods?.some((m) => m.kind === kind) ?? false;
}

/** Classifies a module: imports, exports, helpers, client factories and auth helpers. */
export function analyzeModule(rel: string, sf: ts.SourceFile): ModuleFacts {
  const imports = new Map<string, ImportRef>();
  const reexports: Reexport[] = [];
  const exportedNames = new Set<string>();
  let defaultExport: string | null = null;
  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
      const spec = stmt.moduleSpecifier.text;
      const clause = stmt.importClause;
      if (!clause) continue;
      if (clause.name) imports.set(clause.name.text, { spec, imported: "default" });
      const nb = clause.namedBindings;
      if (nb && ts.isNamedImports(nb)) {
        for (const el of nb.elements) {
          imports.set(el.name.text, { spec, imported: (el.propertyName ?? el.name).text });
        }
      }
      if (nb && ts.isNamespaceImport(nb)) imports.set(nb.name.text, { spec, imported: "*" });
    } else if (ts.isExportDeclaration(stmt)) {
      const spec =
        stmt.moduleSpecifier && ts.isStringLiteral(stmt.moduleSpecifier)
          ? stmt.moduleSpecifier.text
          : null;
      const clause = stmt.exportClause;
      if (spec && !clause) reexports.push({ star: true, spec });
      else if (clause && ts.isNamedExports(clause)) {
        for (const el of clause.elements) {
          const name = (el.propertyName ?? el.name).text;
          if (spec) reexports.push({ star: false, name, alias: el.name.text, spec });
          else exportedNames.add(name);
        }
      }
    } else if (ts.isExportAssignment(stmt) && !stmt.isExportEquals) {
      const e = unwrap(stmt.expression);
      if (ts.isIdentifier(e)) defaultExport = e.text;
    } else if (
      ts.isFunctionDeclaration(stmt) &&
      stmt.name &&
      hasModifier(stmt, ts.SyntaxKind.DefaultKeyword)
    ) {
      defaultExport = stmt.name.text;
    }
  }

  const functions = new Map<string, TopLevelFunction>();
  for (const f of topLevelFunctions(sf)) {
    functions.set(f.name, exportedNames.has(f.name) ? { ...f, exported: true } : f);
  }
  const classes = new Map<string, ClassInfo>();
  for (const c of classesIn(sf)) {
    classes.set(c.name, exportedNames.has(c.name) ? { ...c, exported: true } : c);
  }
  const moduleVars = new Map<string, ModuleVar>();
  for (const stmt of sf.statements) {
    if (!ts.isVariableStatement(stmt)) continue;
    const exported = hasModifier(stmt, ts.SyntaxKind.ExportKeyword);
    for (const d of stmt.declarationList.declarations) {
      if (!ts.isIdentifier(d.name) || !d.initializer || functions.has(d.name.text)) continue;
      const init = unwrap(d.initializer);
      if (!ts.isCallExpression(init) && !ts.isNewExpression(init)) continue;
      moduleVars.set(d.name.text, {
        name: d.name.text,
        init,
        exported: exported || exportedNames.has(d.name.text),
        node: d,
      });
    }
  }

  const clientFactories: ClientFactory[] = [];
  const authHelpers: AuthHelper[] = [];
  for (const f of functions.values()) {
    const text = f.fn.getText(sf);
    const location = { file: rel, line: lineOf(sf, f.node) };
    if (AUTH_CALL.test(text)) {
      authHelpers.push({
        name: f.name,
        location,
        evidence: "calls supabase auth.getUser/getSession/getClaims",
      });
      continue;
    }
    const creates = collect(f.fn, ts.isCallExpression).filter((c) => isCreateClientCall(c, sf));
    const first = creates[0];
    if (first) {
      const { kind, evidence } = classifyCreateClientCall(first, sf);
      clientFactories.push({ name: f.name, kind, location, evidence });
    }
  }
  return {
    file: rel,
    clientFactories,
    authHelpers,
    imports,
    functions,
    classes,
    moduleVars,
    reexports,
    defaultExport,
  };
}
