import ts from "typescript";
import { collect, exportedFunctions, lineOf, unwrap } from "./ast.js";
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
  if (/SERVICE_ROLE|service_role|SECRET_KEY|SB_SECRET|sb_secret/i.test(keyArg)) {
    return {
      kind: "service_role",
      evidence: `key ${keyArg} is a service-role secret; RLS is bypassed`,
    };
  }
  const anonKey = /ANON|PUBLISHABLE|anon|publishable/.test(keyArg);
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

export interface ModuleFacts {
  file: string;
  clientFactories: ClientFactory[];
  authHelpers: AuthHelper[];
  /** local import name -> module specifier */
  imports: Map<string, string>;
}

/** Classifies a module's exported helpers: Supabase client factories and auth helpers. */
export function analyzeModule(rel: string, sf: ts.SourceFile): ModuleFacts {
  const imports = new Map<string, string>();
  for (const stmt of sf.statements) {
    if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
    const spec = stmt.moduleSpecifier.text;
    const clause = stmt.importClause;
    if (!clause) continue;
    if (clause.name) imports.set(clause.name.text, spec);
    const nb = clause.namedBindings;
    if (nb && ts.isNamedImports(nb)) for (const el of nb.elements) imports.set(el.name.text, spec);
    if (nb && ts.isNamespaceImport(nb)) imports.set(nb.name.text, spec);
  }

  const clientFactories: ClientFactory[] = [];
  const authHelpers: AuthHelper[] = [];
  for (const ex of exportedFunctions(sf)) {
    const text = ex.fn.getText(sf);
    const location = { file: rel, line: lineOf(sf, ex.node) };
    if (AUTH_CALL.test(text)) {
      authHelpers.push({
        name: ex.name,
        location,
        evidence: "calls supabase auth.getUser/getSession/getClaims",
      });
      continue;
    }
    const creates = collect(ex.fn, ts.isCallExpression).filter((c) => isCreateClientCall(c, sf));
    const first = creates[0];
    if (first) {
      const { kind, evidence } = classifyCreateClientCall(first, sf);
      clientFactories.push({ name: ex.name, kind, location, evidence });
    }
  }
  return { file: rel, clientFactories, authHelpers, imports };
}
