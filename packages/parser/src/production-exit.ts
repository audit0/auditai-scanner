import ts from "typescript";
import { type FunctionLike, lineOf } from "./ast.js";
import type { FileRef } from "./model.js";

/**
 * A development-only route: the handler's first statement is `if (<condition>) return …` (or
 * `throw …`), the condition is true when NODE_ENV is "production" (the value Next.js inlines into
 * every production build), and what the branch returns or throws is an answer built on the spot.
 * Such a route does not exist in production.
 *
 * Deliberately narrow. The condition is read, not evaluated in general: it may only combine, with
 * `!`, `&&`, `||` and parentheses,
 *   - `process.env.NODE_ENV` compared (`===`, `==`, `!==`, `!=`) with a string literal, and
 *   - a call without arguments to a function declared once at the top level of the same module,
 *     never reassigned or shadowed, whose own first statement is `if (<such a condition>) return
 *     true|false` (the git-city `devLoginAllowed()` shape), one level deep.
 * Anything else (an import, a method, an argument, an `await`, a helper that decides later) leaves
 * the answer unknown and the finding stays.
 *
 * The production branch must be that one statement and nothing else, and its expression may only
 * build an answer (answerOnly): a query inside the branch runs only in production, exactly where
 * the route would be taken for absent (review cx7), and `return helper()` runs whatever the helper
 * does (cx7b).
 */
export function productionExitOf(
  sf: ts.SourceFile,
  fn: FunctionLike,
  file: string,
): FileRef | null {
  const body = fn.body;
  if (!body || !ts.isBlock(body)) return null;
  const first = body.statements[0];
  if (!first || !ts.isIfStatement(first) || first.elseStatement) return null;
  const then = first.thenStatement;
  const only = ts.isBlock(then) ? (then.statements.length === 1 ? then.statements[0] : null) : then;
  if (!only || (!ts.isReturnStatement(only) && !ts.isThrowStatement(only))) return null;
  if (only.expression && !answerOnly(sf, fn, only.expression)) return null;
  const shadowed = new Set([...topLevelNames(sf), ...declaredIn(fn)]);
  if (shadowed.has("process") || countTopLevel(sf, "process") > 0) return null;
  return inProduction(first.expression, sf, fn, 0) === true
    ? { file, line: lineOf(sf, first) }
    : null;
}

/** The condition's value in a production build: true, false, or null when it is not read. */
function inProduction(
  e: ts.Expression,
  sf: ts.SourceFile,
  fn: FunctionLike,
  depth: number,
): boolean | null {
  let x = e;
  while (ts.isParenthesizedExpression(x)) x = x.expression;
  if (ts.isPrefixUnaryExpression(x) && x.operator === ts.SyntaxKind.ExclamationToken) {
    const v = inProduction(x.operand, sf, fn, depth);
    return v === null ? null : !v;
  }
  if (ts.isBinaryExpression(x)) {
    const op = x.operatorToken.kind;
    if (op === ts.SyntaxKind.AmpersandAmpersandToken || op === ts.SyntaxKind.BarBarToken) {
      const l = inProduction(x.left, sf, fn, depth);
      const r = inProduction(x.right, sf, fn, depth);
      if (op === ts.SyntaxKind.AmpersandAmpersandToken) {
        if (l === false || r === false) return false;
        return l === true && r === true ? true : null;
      }
      if (l === true || r === true) return true;
      return l === false && r === false ? false : null;
    }
    const eq =
      op === ts.SyntaxKind.EqualsEqualsEqualsToken || op === ts.SyntaxKind.EqualsEqualsToken;
    const ne =
      op === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
      op === ts.SyntaxKind.ExclamationEqualsToken;
    if (!eq && !ne) return null;
    const lit = isNodeEnv(x.left)
      ? stringLiteral(x.right)
      : isNodeEnv(x.right)
        ? stringLiteral(x.left)
        : null;
    if (lit === null) return null;
    return (lit === "production") === eq;
  }
  if (ts.isCallExpression(x) && depth === 0) return helperAnswer(x, sf, fn);
  return null;
}

/** `process.env.NODE_ENV` or `process.env["NODE_ENV"]`. */
function isNodeEnv(e: ts.Expression): boolean {
  let x = e;
  while (ts.isParenthesizedExpression(x)) x = x.expression;
  let recv: ts.Expression;
  if (ts.isPropertyAccessExpression(x) && x.name.text === "NODE_ENV") recv = x.expression;
  else if (
    ts.isElementAccessExpression(x) &&
    ts.isStringLiteral(x.argumentExpression) &&
    x.argumentExpression.text === "NODE_ENV"
  ) {
    recv = x.expression;
  } else return false;
  return (
    ts.isPropertyAccessExpression(recv) &&
    recv.name.text === "env" &&
    ts.isIdentifier(recv.expression) &&
    recv.expression.text === "process"
  );
}

function stringLiteral(e: ts.Expression): string | null {
  let x = e;
  while (ts.isParenthesizedExpression(x)) x = x.expression;
  return ts.isStringLiteral(x) || ts.isNoSubstitutionTemplateLiteral(x) ? x.text : null;
}

/**
 * `helper()` where `helper` is a plain function declared once at the module's top level, never
 * assigned, not shadowed in the handler, and its first statement is `if (C) return true|false` with
 * C true in production: its value in production is that literal.
 */
function helperAnswer(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  handler: FunctionLike,
): boolean | null {
  if (!ts.isIdentifier(call.expression) || call.arguments.length > 0 || call.questionDotToken) {
    return null;
  }
  const name = call.expression.text;
  if (declaredIn(handler).has(name) || countTopLevel(sf, name) !== 1) return null;
  const decl = sf.statements.find(
    (s): s is ts.FunctionDeclaration => ts.isFunctionDeclaration(s) && s.name?.text === name,
  );
  if (!decl || !onlyCalled(sf, name, decl)) return null;
  if (!decl.body || decl.asteriskToken || decl.parameters.length > 0) return null;
  if (decl.modifiers?.some((m) => m.kind === ts.SyntaxKind.AsyncKeyword)) return null;
  const first = decl.body.statements[0];
  if (!first || !ts.isIfStatement(first) || first.elseStatement) return null;
  const then = first.thenStatement;
  const only = ts.isBlock(then) ? (then.statements.length === 1 ? then.statements[0] : null) : then;
  if (!only || !ts.isReturnStatement(only) || !only.expression) return null;
  const k = only.expression.kind;
  if (k !== ts.SyntaxKind.TrueKeyword && k !== ts.SyntaxKind.FalseKeyword) return null;
  if (declaredIn(decl).has("process")) return null;
  return inProduction(first.expression, sf, decl, 1) === true
    ? k === ts.SyntaxKind.TrueKeyword
    : null;
}

/**
 * An expression that only builds an answer: no `await`, no function of its own, no assignment, and
 * no call but `NextResponse.*` imported from next/server, the global `Response.*` and `JSON.*`,
 * `notFound()`/`forbidden()`/`unauthorized()` imported from next/navigation, and `new` of
 * NextResponse, Response, URL or an `*Error` that nothing in the module or handler declares.
 */
function answerOnly(sf: ts.SourceFile, fn: FunctionLike, e: ts.Expression): boolean {
  const local = new Set<string>([...topLevelNames(sf), ...declaredIn(fn)]);
  const global = (name: string): boolean => !local.has(name);
  const fromPackage = (name: string, spec: string): string | null =>
    declaredIn(fn).has(name) ? null : importedName(sf, name, spec);
  let ok = true;
  const visit = (n: ts.Node): void => {
    if (!ok) return;
    if (
      ts.isAwaitExpression(n) ||
      ts.isYieldExpression(n) ||
      ts.isTaggedTemplateExpression(n) ||
      ts.isDeleteExpression(n) ||
      ts.isArrowFunction(n) ||
      ts.isFunctionExpression(n) ||
      ts.isClassExpression(n) ||
      (ts.isBinaryExpression(n) &&
        n.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
        n.operatorToken.kind <= ts.SyntaxKind.LastAssignment) ||
      ((ts.isPrefixUnaryExpression(n) || ts.isPostfixUnaryExpression(n)) &&
        (n.operator === ts.SyntaxKind.PlusPlusToken ||
          n.operator === ts.SyntaxKind.MinusMinusToken))
    ) {
      ok = false;
      return;
    }
    if (ts.isCallExpression(n)) {
      const c = n.expression;
      const allowed =
        (ts.isPropertyAccessExpression(c) &&
          ts.isIdentifier(c.expression) &&
          ((c.expression.text === "NextResponse" &&
            fromPackage("NextResponse", "next/server") === "NextResponse") ||
            ((c.expression.text === "Response" || c.expression.text === "JSON") &&
              global(c.expression.text)))) ||
        (ts.isIdentifier(c) &&
          /^(notFound|forbidden|unauthorized)$/.test(fromPackage(c.text, "next/navigation") ?? ""));
      if (!allowed) {
        ok = false;
        return;
      }
    }
    if (ts.isNewExpression(n)) {
      const c = n.expression;
      const allowed =
        ts.isIdentifier(c) &&
        ((c.text === "NextResponse" &&
          fromPackage("NextResponse", "next/server") === "NextResponse") ||
          ((c.text === "Response" ||
            c.text === "URL" ||
            /^(?:[A-Z][A-Za-z]*)?Error$/.test(c.text)) &&
            global(c.text)));
      if (!allowed) {
        ok = false;
        return;
      }
    }
    n.forEachChild(visit);
  };
  visit(e);
  return ok;
}

/** The name a value import of `local` from `spec` brings in, or null (namespace and type imports: null). */
function importedName(sf: ts.SourceFile, local: string, spec: string): string | null {
  if (countTopLevel(sf, local) !== 1) return null;
  for (const s of sf.statements) {
    if (!ts.isImportDeclaration(s) || !ts.isStringLiteral(s.moduleSpecifier)) continue;
    if (s.moduleSpecifier.text !== spec || !s.importClause || s.importClause.isTypeOnly) continue;
    const nb = s.importClause.namedBindings;
    if (!nb || !ts.isNamedImports(nb)) continue;
    for (const el of nb.elements) {
      if (el.name.text === local && !el.isTypeOnly) return (el.propertyName ?? el.name).text;
    }
  }
  return null;
}

/** Every name bound by a binding pattern or identifier. */
function boundNames(n: ts.BindingName): string[] {
  if (ts.isIdentifier(n)) return [n.text];
  const out: string[] = [];
  for (const el of n.elements) if (!ts.isOmittedExpression(el)) out.push(...boundNames(el.name));
  return out;
}

/** Every name the module declares at its top level, imports included (with repeats). */
function topLevelList(sf: ts.SourceFile): string[] {
  const out: string[] = [];
  for (const s of sf.statements) {
    if (ts.isVariableStatement(s)) {
      for (const d of s.declarationList.declarations) out.push(...boundNames(d.name));
    } else if (
      (ts.isFunctionDeclaration(s) ||
        ts.isClassDeclaration(s) ||
        ts.isEnumDeclaration(s) ||
        ts.isModuleDeclaration(s)) &&
      s.name &&
      ts.isIdentifier(s.name)
    ) {
      out.push(s.name.text);
    } else if (ts.isImportDeclaration(s) && s.importClause) {
      const c = s.importClause;
      if (c.name) out.push(c.name.text);
      const nb = c.namedBindings;
      if (nb && ts.isNamespaceImport(nb)) out.push(nb.name.text);
      else if (nb) for (const el of nb.elements) out.push(el.name.text);
    } else if (ts.isImportEqualsDeclaration(s)) {
      out.push(s.name.text);
    }
  }
  return out;
}

function topLevelNames(sf: ts.SourceFile): Set<string> {
  return new Set(topLevelList(sf));
}

function countTopLevel(sf: ts.SourceFile, name: string): number {
  return topLevelList(sf).filter((n) => n === name).length;
}

/** Every name declared anywhere inside a function (parameters, locals, nested functions and theirs). */
function declaredIn(fn: FunctionLike): Set<string> {
  const out = new Set<string>();
  const visit = (n: ts.Node): void => {
    if (ts.isParameter(n) || ts.isVariableDeclaration(n) || ts.isBindingElement(n)) {
      for (const b of boundNames(n.name)) out.add(b);
    } else if (
      (ts.isFunctionDeclaration(n) || ts.isClassDeclaration(n) || ts.isFunctionExpression(n)) &&
      n.name
    ) {
      out.add(n.name.text);
    } else if (ts.isCatchClause(n) && n.variableDeclaration) {
      for (const b of boundNames(n.variableDeclaration.name)) out.add(b);
    }
    n.forEachChild(visit);
  };
  for (const p of fn.parameters) visit(p);
  if (fn.body) visit(fn.body);
  return out;
}

/**
 * Every mention of the name in the module is the declaration itself or the callee of a call: the
 * function is never reassigned, passed, exported under another name or read as a value.
 */
function onlyCalled(sf: ts.SourceFile, name: string, decl: ts.FunctionDeclaration): boolean {
  let ok = true;
  const visit = (n: ts.Node): void => {
    if (!ok) return;
    if (ts.isIdentifier(n) && n.text === name && n !== decl.name) {
      const p = n.parent;
      if (!(ts.isCallExpression(p) && p.expression === n)) ok = false;
    }
    n.forEachChild(visit);
  };
  visit(sf);
  return ok;
}
