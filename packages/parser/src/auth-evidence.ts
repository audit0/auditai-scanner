import ts from "typescript";
import {
  type FunctionLike,
  identifiersIn,
  isFunctionLikeNode,
  ownReturns,
  topLevelFunctions,
  unwrap,
  walkOwn,
} from "./ast.js";

/**
 * Authentication that is not `supabase.auth.getUser()`: a request credential compared with a server
 * secret (cron secret, admin password, API key in an env variable), a signature or token verified
 * with one, a session from a known auth library, or a credential looked up by its hash. Every check
 * here needs evidence in the code; a helper merely named `auth` or `requireAdmin` proves nothing.
 */

/** Env names that hold a server-side secret. */
const SECRET_ENV_NAME = /SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE|API_?KEY|PRIVATE|_KEY$|^KEY$/i;
/** Public configuration: the anon/publishable key and anything Next.js ships to the browser. */
const PUBLIC_ENV_NAME = /^NEXT_PUBLIC_|ANON|PUBLISHABLE|PUBLIC/i;

export function isSecretEnvName(name: string): boolean {
  return SECRET_ENV_NAME.test(name) && !PUBLIC_ENV_NAME.test(name);
}

function isEnvObject(e: ts.Expression): boolean {
  const u = unwrap(e);
  if (ts.isIdentifier(u)) return /env$/i.test(u.text);
  return (
    ts.isPropertyAccessExpression(u) &&
    u.name.text === "env" &&
    ts.isIdentifier(u.expression) &&
    u.expression.text === "process"
  );
}

function calleeName(callee: ts.Expression): string {
  if (ts.isIdentifier(callee)) return callee.text;
  if (ts.isPropertyAccessExpression(callee)) return callee.name.text;
  return "";
}

/**
 * Env variables read by an expression: `process.env.CRON_SECRET`, `process.env["X"]`, `env.X`
 * (t3-env style objects), `getRuntimeEnv("ADMIN_PASSWORD")`.
 */
export function envNamesIn(node: ts.Node): string[] {
  const out: string[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isPropertyAccessExpression(n) && isEnvObject(n.expression)) out.push(n.name.text);
    else if (
      ts.isElementAccessExpression(n) &&
      isEnvObject(n.expression) &&
      ts.isStringLiteralLike(n.argumentExpression)
    ) {
      out.push(n.argumentExpression.text);
    } else if (ts.isCallExpression(n) && /env/i.test(calleeName(n.expression))) {
      const first = n.arguments[0];
      if (first && ts.isStringLiteralLike(first)) out.push(first.text);
    }
    n.forEachChild(visit);
  };
  visit(node);
  return out;
}

/** What a module knows about secrets: constants holding one, and functions returning one. */
interface SecretScope {
  names: Set<string>;
  /** Same-module functions whose result derives from a secret (`signPayload()` = HMAC with the session secret). */
  fns: Set<string>;
}

const moduleScopes = new WeakMap<ts.SourceFile, SecretScope>();

/** Adds every declaration whose initializer derives from a known secret; iterates for chains of hops. */
function growNames(decls: readonly ts.VariableDeclaration[], scope: SecretScope): void {
  // `const expected = process.env.X; const expectedBuf = Buffer.from(expected)`: two hops, so iterate.
  for (let pass = 0; pass < 3; pass++) {
    const before = scope.names.size;
    for (const d of decls) {
      if (!ts.isIdentifier(d.name) || !d.initializer || scope.names.has(d.name.text)) continue;
      if (isSecretish(d.initializer, scope)) scope.names.add(d.name.text);
    }
    if (scope.names.size === before) break;
  }
}

function ownDeclarations(fn: FunctionLike): ts.VariableDeclaration[] {
  const out: ts.VariableDeclaration[] = [];
  if (fn.body) {
    walkOwn(fn.body, (n) => {
      if (ts.isVariableDeclaration(n)) out.push(n);
    });
  }
  return out;
}

function moduleSecretScope(sf: ts.SourceFile): SecretScope {
  const cached = moduleScopes.get(sf);
  if (cached) return cached;
  const scope: SecretScope = { names: new Set(), fns: new Set() };
  const decls: ts.VariableDeclaration[] = [];
  for (const stmt of sf.statements) {
    if (ts.isVariableStatement(stmt)) decls.push(...stmt.declarationList.declarations);
  }
  const fns = topLevelFunctions(sf);
  for (let pass = 0; pass < 3; pass++) {
    const before = scope.names.size + scope.fns.size;
    growNames(decls, scope);
    for (const f of fns) {
      if (scope.fns.has(f.name)) continue;
      const local: SecretScope = { names: new Set(scope.names), fns: scope.fns };
      growNames(ownDeclarations(f.fn), local);
      if (ownReturns(f.fn).some((r) => isSecretish(r, local))) scope.fns.add(f.name);
    }
    if (scope.names.size + scope.fns.size === before) break;
  }
  moduleScopes.set(sf, scope);
  return scope;
}

/** Names bound (in this function or at module level) to a value derived from a server secret. */
function secretScopeFor(fn: FunctionLike, sf: ts.SourceFile): SecretScope {
  const mod = moduleSecretScope(sf);
  const scope: SecretScope = { names: new Set(mod.names), fns: mod.fns };
  growNames(ownDeclarations(fn), scope);
  return scope;
}

function isSecretish(e: ts.Node, scope: SecretScope): boolean {
  if (envNamesIn(e).some(isSecretEnvName)) return true;
  for (const id of identifiersIn(e)) if (scope.names.has(id)) return true;
  let calls = false;
  const visit = (n: ts.Node): void => {
    if (calls) return;
    if (
      ts.isCallExpression(n) &&
      ts.isIdentifier(n.expression) &&
      scope.fns.has(n.expression.text)
    ) {
      calls = true;
      return;
    }
    n.forEachChild(visit);
  };
  visit(e);
  return calls;
}

function isLiteralish(e: ts.Expression): boolean {
  const u = unwrap(e);
  return (
    ts.isStringLiteralLike(u) ||
    ts.isNumericLiteral(u) ||
    u.kind === ts.SyntaxKind.NullKeyword ||
    u.kind === ts.SyntaxKind.TrueKeyword ||
    u.kind === ts.SyntaxKind.FalseKeyword ||
    ts.isTypeOfExpression(u) ||
    (ts.isIdentifier(u) && u.text === "undefined")
  );
}

const EQUALITY = new Set([
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
]);
/** Constant-time and plain comparison helpers. */
const COMPARE_CALLEE =
  /^(timingSafeEqual|safeCompare|secureCompare|safeEqual|constantTimeEqual|constantTimeCompare|timingSafeCompare|compare|compareSync|isEqual|equals?)$/i;
/** Signature and token verification with a key. */
const VERIFY_CALLEE =
  /^(verify|verifySync|jwtVerify|constructEvent|constructEventAsync|verifySignature|verifyWebhook|validateSignature)$/i;
/** Verifiers that throw on a bad credential, so an unhandled call already stops the request. */
const THROWING_VERIFIER = /^(jwtVerify|constructEvent|constructEventAsync)$/;
/** `jwt.verify(token, secret)` (jsonwebtoken) throws too; `crypto.verify(...)` returns a boolean. */
const THROWING_VERIFY_RECEIVER = /jwt|jose|jsonwebtoken/i;

function throwsOnBadCredential(call: ts.CallExpression): boolean {
  const callee = call.expression;
  if (THROWING_VERIFIER.test(calleeName(callee))) return true;
  return (
    ts.isPropertyAccessExpression(callee) &&
    callee.name.text === "verify" &&
    THROWING_VERIFY_RECEIVER.test(callee.expression.getText())
  );
}
/** Next.js navigation helpers throw: calling one ends the request. */
const THROWING_NAV = /^(redirect|permanentRedirect|notFound|unauthorized|forbidden)$/;

/** Does a statement stop the function (return, throw, or a Next.js redirect/notFound)? */
export function exitKind(stmt: ts.Node): "throw" | "return" | null {
  let kind: "throw" | "return" | null = null;
  walkOwn(stmt, (n) => {
    if (ts.isThrowStatement(n)) kind = "throw";
    else if (ts.isCallExpression(n) && THROWING_NAV.test(calleeName(n.expression))) kind = "throw";
    else if (ts.isReturnStatement(n) && kind === null) kind = "return";
  });
  return kind;
}

function ifExits(s: ts.IfStatement): boolean {
  return (
    exitKind(s.thenStatement) !== null ||
    (s.elseStatement ? exitKind(s.elseStatement) : null) !== null
  );
}

function referencedInExitingIf(name: string, fnBody: ts.Node, after: number): boolean {
  let hit = false;
  walkOwn(fnBody, (n) => {
    if (hit || n.pos < after) return;
    if (ts.isIfStatement(n) && identifiersIn(n.expression).has(name) && ifExits(n)) hit = true;
    else if (ts.isReturnStatement(n) && n.expression && identifiersIn(n.expression).has(name)) {
      hit = true;
    }
  });
  return hit;
}

/**
 * The comparison decides what happens next: it is the condition of an `if` that returns or throws,
 * it is returned (a predicate helper whose caller branches on it), it initialises a variable used that
 * way, or it sits in a `try` whose `catch` returns or throws.
 */
function gates(node: ts.Node, fnBody: ts.Node): boolean {
  let child: ts.Node = node;
  let cur: ts.Node | undefined = node.parent;
  while (cur && cur !== fnBody && !isFunctionLikeNode(cur)) {
    if (ts.isIfStatement(cur)) return cur.expression === child && ifExits(cur);
    if (ts.isReturnStatement(cur)) return true;
    if (ts.isVariableDeclaration(cur) && ts.isIdentifier(cur.name) && cur.initializer === child) {
      return referencedInExitingIf(cur.name.text, fnBody, cur.end);
    }
    if (ts.isTryStatement(cur) && cur.tryBlock === child && cur.catchClause) {
      return exitKind(cur.catchClause.block) !== null;
    }
    if (ts.isExpressionStatement(cur) || ts.isBlock(cur)) return false;
    child = cur;
    cur = cur.parent;
  }
  return false;
}

export interface SecretCheck {
  node: ts.Node;
  /** What was found, for evidence: `x-cron-secret header === process.env.CRON_SECRET`. */
  text: string;
}

/**
 * Comparisons of a caller-supplied value with a server secret that decide the request's fate, in
 * the function's own statements: `if (req.headers.get("authorization") !== \`Bearer ${process.env.CRON_SECRET}\`) return 401`,
 * `return timingSafeEqual(token, secret)`, `jwt.verify(token, process.env.JWT_SECRET)`.
 */
export function secretChecksIn(fn: FunctionLike, sf: ts.SourceFile): SecretCheck[] {
  if (!fn.body) return [];
  const body = fn.body;
  const secrets = secretScopeFor(fn, sf);
  const secretish = (e: ts.Expression): boolean => isSecretish(e, secrets);
  const out: SecretCheck[] = [];
  const push = (n: ts.Node): void => {
    out.push({ node: n, text: n.getText(sf).replace(/\s+/g, " ").slice(0, 160) });
  };
  walkOwn(body, (n) => {
    if (ts.isBinaryExpression(n) && EQUALITY.has(n.operatorToken.kind)) {
      const [a, b] = [n.left, n.right];
      const oneSecret = secretish(a) !== secretish(b);
      const other = secretish(a) ? b : a;
      if (oneSecret && !isLiteralish(other) && gates(n, body)) push(n);
      return;
    }
    if (!ts.isCallExpression(n)) return;
    const name = calleeName(n.expression);
    const compare = COMPARE_CALLEE.test(name);
    const verify = VERIFY_CALLEE.test(name);
    if (!compare && !verify) return;
    const secretArgs = n.arguments.filter(secretish).length;
    if (secretArgs === 0 || secretArgs === n.arguments.length) return;
    if ((verify && throwsOnBadCredential(n)) || gates(n, body)) push(n);
  });
  return out;
}

/** Session functions of auth libraries, by import specifier. */
const SESSION_PROVIDERS: ReadonlyArray<{ spec: RegExp; names: ReadonlySet<string> }> = [
  { spec: /^next-auth(\/next)?$/, names: new Set(["getServerSession"]) },
  { spec: /^@clerk\/nextjs(\/server)?$/, names: new Set(["auth", "currentUser"]) },
];

/** `getServerSession` from next-auth, `auth()`/`currentUser()` from Clerk. */
export function isSessionProviderImport(spec: string, imported: string): boolean {
  return SESSION_PROVIDERS.some((p) => p.spec.test(spec) && p.names.has(imported));
}

/** `export const { auth, handlers } = NextAuth(config)` (Auth.js v5): the names that return the session. */
export function nextAuthSessionNames(
  stmt: ts.VariableStatement,
  nextAuthLocal: ReadonlySet<string>,
): string[] {
  const out: string[] = [];
  for (const d of stmt.declarationList.declarations) {
    if (!ts.isObjectBindingPattern(d.name) || !d.initializer) continue;
    const init = unwrap(d.initializer);
    if (!ts.isCallExpression(init) || !ts.isIdentifier(init.expression)) continue;
    if (!nextAuthLocal.has(init.expression.text)) continue;
    for (const el of d.name.elements) {
      const prop = el.propertyName ?? el.name;
      if (ts.isIdentifier(prop) && prop.text === "auth" && ts.isIdentifier(el.name)) {
        out.push(el.name.text);
      }
    }
  }
  return out;
}

/**
 * A column holding a credential: a query that looks the caller up by it with a request value is the
 * authentication step itself (`api_keys.key_hash = sha256(bearer)`).
 */
const CREDENTIAL_COLUMN =
  /(keyhash|tokenhash|hashedkey|hashedtoken|secrethash|apikey|apikeyhash|apitoken|accesstoken|sessiontoken|secret)$/;

export function isCredentialColumn(column: string | null): boolean {
  return column !== null && CREDENTIAL_COLUMN.test(column.toLowerCase().replace(/_/g, ""));
}
