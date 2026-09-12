import ts from "typescript";
import { boundNames, enclosingFunction, identifiersIn, unwrap, walkOwn } from "./ast.js";
import { exitKind } from "./auth-evidence.js";

/**
 * Guard queries: "read the row through RLS (or filtered by the caller), stop if it is missing, then
 * act on it with the service role". The read is a guard only when a missing row actually stops the
 * entry point, so these helpers find that stop.
 */

export type ExitKind = "throw" | "return";

/** Walks up from an expression through `await`, parentheses, casts and `!`. */
function outerOf(node: ts.Node): { node: ts.Node; parent: ts.Node | undefined } {
  let cur: ts.Node = node;
  let parent = cur.parent;
  while (
    parent &&
    (ts.isAwaitExpression(parent) ||
      ts.isParenthesizedExpression(parent) ||
      ts.isAsExpression(parent) ||
      ts.isNonNullExpression(parent) ||
      ts.isSatisfiesExpression(parent) ||
      ts.isTypeAssertionExpression(parent))
  ) {
    cur = parent;
    parent = cur.parent;
  }
  return { node: cur, parent };
}

function rootName(e: ts.Expression): string | null {
  const u = unwrap(e);
  if (ts.isIdentifier(u)) return u.text;
  if (ts.isPropertyAccessExpression(u) || ts.isElementAccessExpression(u)) {
    return rootName(u.expression);
  }
  return null;
}

function isNullish(e: ts.Expression): boolean {
  const u = unwrap(e);
  return u.kind === ts.SyntaxKind.NullKeyword || (ts.isIdentifier(u) && u.text === "undefined");
}

function isZero(e: ts.Expression): boolean {
  const u = unwrap(e);
  return ts.isNumericLiteral(u) && u.text === "0";
}

/** `!row`, `!row?.id`, `row === null`, `rows.length === 0`, `!data || error`: true when the row is missing. */
export function checksMissing(cond: ts.Expression, names: ReadonlySet<string>): boolean {
  const u = unwrap(cond);
  if (ts.isPrefixUnaryExpression(u) && u.operator === ts.SyntaxKind.ExclamationToken) {
    const r = rootName(u.operand);
    return r !== null && names.has(r);
  }
  if (!ts.isBinaryExpression(u)) return false;
  const op = u.operatorToken.kind;
  if (op === ts.SyntaxKind.BarBarToken) {
    return checksMissing(u.left, names) || checksMissing(u.right, names);
  }
  if (op !== ts.SyntaxKind.EqualsEqualsEqualsToken && op !== ts.SyntaxKind.EqualsEqualsToken) {
    return false;
  }
  for (const [a, b] of [
    [u.left, u.right],
    [u.right, u.left],
  ] as const) {
    const r = rootName(a);
    if (r === null || !names.has(r)) continue;
    if (isNullish(b)) return true;
    const ua = unwrap(a);
    if (ts.isPropertyAccessExpression(ua) && ua.name.text === "length" && isZero(b)) return true;
  }
  return false;
}

function mentions(cond: ts.Expression, names: ReadonlySet<string>): boolean {
  for (const id of identifiersIn(cond)) if (names.has(id)) return true;
  return false;
}

/** The statements that run after `node` in its function (or module), outside nested functions. */
function ifsAfter(node: ts.Node): ts.IfStatement[] {
  const fn = enclosingFunction(node);
  const scope: ts.Node | undefined = fn ? fn.body : node.getSourceFile();
  const out: ts.IfStatement[] = [];
  if (!scope) return out;
  walkOwn(scope, (n) => {
    if (ts.isIfStatement(n) && n.pos >= node.end) out.push(n);
  });
  return out;
}

/** Names bound from a query result: `data` and `error` of `{ data, error }`, a plain row, `[row]`. */
function resultNames(name: ts.BindingName): { data: Set<string>; error: Set<string> } {
  const data = new Set<string>();
  const error = new Set<string>();
  if (ts.isIdentifier(name)) data.add(name.text);
  else if (ts.isArrayBindingPattern(name)) {
    const first = name.elements[0];
    if (first && !ts.isOmittedExpression(first))
      for (const n of boundNames(first.name)) data.add(n);
  } else {
    for (const el of name.elements) {
      const prop = el.propertyName ?? el.name;
      const key = ts.isIdentifier(prop) ? prop.text : null;
      if (key === "data") for (const n of boundNames(el.name)) data.add(n);
      else if (key === "error") for (const n of boundNames(el.name)) error.add(n);
    }
  }
  return { data, error };
}

const THROWING_READ = /^(findUniqueOrThrow|findFirstOrThrow|throwOnError)$/;

/**
 * How the function that runs a query stops when the query finds no row: the result is checked
 * (`if (!flow) return …`, or `if (error)` after `.single()`, which errors on zero rows) and the branch
 * returns or throws. Prisma's `findUniqueOrThrow` throws by itself. Null when nothing stops it.
 */
export function missingRowExit(
  tail: ts.CallExpression,
  segments: readonly string[],
): ExitKind | null {
  if (segments.some((s) => THROWING_READ.test(s))) return "throw";
  const { parent } = outerOf(tail);
  if (!parent || !ts.isVariableDeclaration(parent)) return null;
  const { data, error } = resultNames(parent.name);
  const single = segments.includes("single");
  for (const s of ifsAfter(parent)) {
    const onMissing =
      checksMissing(s.expression, data) || (single && mentions(s.expression, error));
    if (!onMissing) continue;
    const kind = exitKind(s.thenStatement);
    if (kind) return kind;
  }
  return null;
}

/**
 * Does the caller stop when this call reports failure? `const guard = await requireOwnership(id); if
 * (!guard.ok) return …`, `if (!(await canEdit(id))) return …`, or `return requireOwnership(id)` (the
 * caller's own caller decides). A bare `await requireOwnership(id);` only stops the caller if the
 * helper throws.
 */
export function callResultChecked(call: ts.CallExpression): boolean {
  const { node, parent } = outerOf(call);
  if (!parent) return false;
  if (ts.isReturnStatement(parent)) return true;
  if (ts.isVariableDeclaration(parent) && parent.initializer === node) {
    const names = new Set(boundNames(parent.name));
    return ifsAfter(parent).some((s) => mentions(s.expression, names) && exitKind(s) !== null);
  }
  // `if (!(await canEdit(id))) return`: the call sits inside the condition itself.
  let cur: ts.Node | undefined = parent;
  let child: ts.Node = node;
  while (cur && ts.isExpression(cur)) {
    child = cur;
    cur = cur.parent;
  }
  return (
    cur !== undefined &&
    ts.isIfStatement(cur) &&
    cur.expression === child &&
    exitKind(cur.thenStatement) !== null
  );
}

/** Source order of two call paths (positions from the entry point down): negative when `a` runs first. */
export function compareOrder(a: readonly number[], b: readonly number[]): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}
