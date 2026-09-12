import ts from "typescript";
import { boundNames, unwrap, walkOwn } from "./ast.js";
import { envNamesIn, exitKind } from "./auth-evidence.js";

/**
 * Role gates (ADR-001): an `if` that returns, throws or redirects when a role or claim of the
 * authenticated session says so. Evidence-based: the value must be read off a binding that holds
 * the session (`const { data: { user } } = await supabase.auth.getUser()`, `const user = await
 * requireUser()`), through a role-like property, and must decide an exit. `user_metadata` never
 * counts (the end user edits it; R5 flags it), nor does `user.id` compared with a row (that is an
 * ownership check, see guards.ts), nor a helper merely named `isAdmin` with no session value in it.
 */

/** Properties of a session that carry a role or a claim the user cannot self-assign. */
const ROLE_PROPERTY = /^(role|roles|app_metadata|is_?admin|is_?superuser|permissions?|claims?)$/i;
/** The e-mail counts only against literals, env values or as a helper argument (`isAdminEmail(user.email)`). */
const EMAIL_PROPERTY = /^email$/i;

export interface RoleGate {
  node: ts.IfStatement;
  source: string;
  exit: "throw" | "return";
}

/** `user.app_metadata?.role` -> ["user", "app_metadata", "role"]; null for anything but a property chain. */
function propertyPath(e: ts.Expression): string[] | null {
  const u = unwrap(e);
  if (ts.isIdentifier(u)) return [u.text];
  if (ts.isPropertyAccessExpression(u)) {
    const base = propertyPath(u.expression);
    return base === null ? null : [...base, u.name.text];
  }
  return null;
}

function isLiteral(e: ts.Expression): boolean {
  const u = unwrap(e);
  return (
    ts.isStringLiteralLike(u) ||
    ts.isNumericLiteral(u) ||
    ts.isArrayLiteralExpression(u) ||
    u.kind === ts.SyntaxKind.TrueKeyword ||
    u.kind === ts.SyntaxKind.FalseKeyword ||
    u.kind === ts.SyntaxKind.NullKeyword
  );
}

/** A session property read that is role-like, or the e-mail; `user_metadata` anywhere disqualifies. */
function sessionClaim(
  e: ts.Expression,
  sessionNames: ReadonlySet<string>,
): { source: string; kind: "role" | "email" } | null {
  const path = propertyPath(e);
  const root = path?.[0];
  const last = path?.[path.length - 1];
  if (!path || path.length < 2 || root === undefined || last === undefined) return null;
  if (!sessionNames.has(root)) return null;
  if (path.some((p) => p === "user_metadata")) return null;
  if (path.some((p) => ROLE_PROPERTY.test(p))) return { source: path.join("."), kind: "role" };
  if (EMAIL_PROPERTY.test(last)) return { source: path.join("."), kind: "email" };
  return null;
}

/** The session claim a condition decides on, if any. */
function claimIn(cond: ts.Expression, sessionNames: ReadonlySet<string>): string | null {
  let found: string | null = null;
  const visit = (n: ts.Node): void => {
    if (found !== null) return;
    if (ts.isCallExpression(n)) {
      // `isAdminEmail(user.email)`, `ADMIN_EMAILS.includes(user.email)`, `hasRole(session, "admin")`.
      for (const a of n.arguments) {
        const c = sessionClaim(a, sessionNames);
        if (c) {
          found = c.source;
          return;
        }
      }
    } else if (ts.isBinaryExpression(n)) {
      for (const [a, b] of [
        [n.left, n.right],
        [n.right, n.left],
      ] as const) {
        const c = sessionClaim(a, sessionNames);
        if (!c) continue;
        // A role compares with anything; the e-mail only with a literal or a server-side value.
        if (c.kind === "role" || isLiteral(b) || envNamesIn(b).length > 0) {
          found = c.source;
          return;
        }
      }
    } else if (ts.isPrefixUnaryExpression(n) || ts.isPropertyAccessExpression(n)) {
      const target = ts.isPrefixUnaryExpression(n) ? n.operand : n;
      const c = sessionClaim(target, sessionNames);
      if (c?.kind === "role" && !ts.isCallExpression(n.parent)) {
        found = c.source;
        return;
      }
    }
    n.forEachChild(visit);
  };
  visit(cond);
  return found;
}

/** Names bound by the declarations whose initializer `isSessionCall` accepts. */
export function sessionNamesIn(
  body: ts.Node,
  isSessionCall: (call: ts.CallExpression) => boolean,
): Set<string> {
  const out = new Set<string>();
  walkOwn(body, (n) => {
    if (!ts.isVariableDeclaration(n) || !n.initializer) return;
    const init = unwrap(n.initializer);
    if (ts.isCallExpression(init) && isSessionCall(init)) {
      for (const nm of boundNames(n.name)) out.add(nm);
    }
  });
  return out;
}

/** Every exiting `if` of the function's own statements whose condition decides on a session claim. */
export function roleGatesIn(body: ts.Node, sessionNames: ReadonlySet<string>): RoleGate[] {
  const out: RoleGate[] = [];
  if (sessionNames.size === 0) return out;
  walkOwn(body, (n) => {
    if (!ts.isIfStatement(n)) return;
    const exit = exitKind(n.thenStatement);
    if (!exit) return;
    const source = claimIn(n.expression, sessionNames);
    if (source !== null) out.push({ node: n, source, exit });
  });
  return out;
}
