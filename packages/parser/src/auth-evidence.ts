import ts from "typescript";
import {
  collect as collectNodes,
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

/**
 * A secret the server stores per account rather than in the environment: `account.webhook_secret`,
 * `row.api_key`, `key.key_hash`. Comparing a caller-supplied value with one of these is the same
 * kind of check as comparing with `process.env.WEBHOOK_SECRET`.
 */
const STORED_SECRET_FIELD = /(^|_)(secret|signing_key|api_key|key_hash|token_hash|hmac_key)$/;

function readsStoredSecret(e: ts.Node): boolean {
  let hit = false;
  const visit = (n: ts.Node): void => {
    if (hit) return;
    if (ts.isPropertyAccessExpression(n) && STORED_SECRET_FIELD.test(n.name.text.toLowerCase())) {
      hit = true;
      return;
    }
    n.forEachChild(visit);
  };
  visit(e);
  return hit;
}

function isSecretish(e: ts.Node, scope: SecretScope): boolean {
  if (envNamesIn(e).some(isSecretEnvName)) return true;
  if (readsStoredSecret(e)) return true;
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
  /^(timingSafeEqual|safeCompare|secureCompare|safeEqual|constantTimeEqual|constantTimeCompare|timingSafeCompare|compare|compareSync|isEqual|equals?|secretsMatch|secretMatch|matchesSecret|tokensMatch|tokenMatches|sameSecret|checkSecret|validSecret|isValidSecret)$/i;
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
/** The module they throw from. A helper of the same name elsewhere may just return a Response. */
const NEXT_NAVIGATION = "next/navigation";

interface NavImports {
  /** Local name -> exported name, for named imports from next/navigation. */
  named: Map<string, string>;
  /** `import * as nav from "next/navigation"`. */
  namespaces: Set<string>;
  /** Names bound anywhere in the file other than by those imports: a use may mean another binding. */
  rebound: Set<string>;
}

const navImportsMemo = new WeakMap<ts.SourceFile, NavImports>();

function navImportsOf(sf: ts.SourceFile): NavImports {
  const cached = navImportsMemo.get(sf);
  if (cached) return cached;
  const named = new Map<string, string>();
  const namespaces = new Set<string>();
  const fromNav = new Set<ts.Node>();
  for (const st of sf.statements) {
    if (!ts.isImportDeclaration(st) || !ts.isStringLiteral(st.moduleSpecifier)) continue;
    if (st.moduleSpecifier.text !== NEXT_NAVIGATION) continue;
    const clause = st.importClause;
    if (!clause || clause.isTypeOnly) continue;
    const bindings = clause.namedBindings;
    if (bindings && ts.isNamespaceImport(bindings)) {
      namespaces.add(bindings.name.text);
      fromNav.add(bindings.name);
    } else if (bindings && ts.isNamedImports(bindings)) {
      for (const el of bindings.elements) {
        if (el.isTypeOnly) continue;
        named.set(el.name.text, (el.propertyName ?? el.name).text);
        fromNav.add(el.name);
      }
    }
  }
  const rebound = new Set<string>();
  const bind = (name: ts.Node | undefined): void => {
    if (!name || fromNav.has(name)) return;
    if (ts.isIdentifier(name)) rebound.add(name.text);
    else if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
      for (const el of name.elements) if (!ts.isOmittedExpression(el)) bind(el.name);
    }
  };
  if (named.size > 0 || namespaces.size > 0) {
    const visit = (n: ts.Node): void => {
      if (
        ts.isVariableDeclaration(n) ||
        ts.isParameter(n) ||
        ts.isBindingElement(n) ||
        ts.isFunctionDeclaration(n) ||
        ts.isFunctionExpression(n) ||
        ts.isClassDeclaration(n) ||
        ts.isClassExpression(n) ||
        ts.isImportSpecifier(n) ||
        ts.isNamespaceImport(n) ||
        ts.isImportClause(n) ||
        ts.isImportEqualsDeclaration(n)
      ) {
        bind(n.name);
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }
  const out = { named, namespaces, rebound };
  navImportsMemo.set(sf, out);
  return out;
}

/**
 * Does the call throw the way Next.js `redirect()`, `notFound()`, `forbidden()` and friends do? Only
 * when the callee is imported from next/navigation (by name, renamed, or through a namespace import)
 * and the name is not bound again anywhere in the file. A local or repository helper called
 * `forbidden` that returns a Response does not stop anything when its result is dropped.
 */
export function isThrowingNavCall(call: ts.CallExpression): boolean {
  const callee = unwrap(call.expression);
  const sf = call.getSourceFile();
  if (ts.isIdentifier(callee)) {
    const nav = navImportsOf(sf);
    const imported = nav.named.get(callee.text);
    return imported !== undefined && THROWING_NAV.test(imported) && !nav.rebound.has(callee.text);
  }
  if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)) {
    const nav = navImportsOf(sf);
    const ns = callee.expression.text;
    return nav.namespaces.has(ns) && !nav.rebound.has(ns) && THROWING_NAV.test(callee.name.text);
  }
  return false;
}

/**
 * Does a statement always stop the function, on every path through it? `return …`, `throw …`, a
 * Next.js `redirect()`/`notFound()` from next/navigation, or a block whose last statement is one of
 * those. Unlike exitKind, `{ if (x) return; log(); }` does not count: it falls through when `x` is
 * false.
 */
export function alwaysStops(stmt: ts.Statement): boolean {
  if (ts.isReturnStatement(stmt) || ts.isThrowStatement(stmt)) return true;
  if (ts.isExpressionStatement(stmt)) {
    let e: ts.Expression = stmt.expression;
    while (ts.isAwaitExpression(e) || ts.isParenthesizedExpression(e)) e = e.expression;
    return ts.isCallExpression(e) && isThrowingNavCall(e);
  }
  if (!ts.isBlock(stmt)) return false;
  const last = stmt.statements[stmt.statements.length - 1];
  return last !== undefined && alwaysStops(last);
}

const NAV_IMPORTS = new WeakMap<ts.SourceFile, Map<string, string>>();

/** Names a module imports from next/navigation: local name -> imported name, `*` for a namespace. */
function navigationImports(sf: ts.SourceFile): Map<string, string> {
  const cached = NAV_IMPORTS.get(sf);
  if (cached) return cached;
  const out = new Map<string, string>();
  for (const s of sf.statements) {
    if (
      !ts.isImportDeclaration(s) ||
      !ts.isStringLiteral(s.moduleSpecifier) ||
      s.moduleSpecifier.text !== "next/navigation" ||
      !s.importClause ||
      s.importClause.isTypeOnly
    ) {
      continue;
    }
    const nb = s.importClause.namedBindings;
    if (nb && ts.isNamespaceImport(nb)) out.set(nb.name.text, "*");
    else if (nb) {
      for (const el of nb.elements) out.set(el.name.text, (el.propertyName ?? el.name).text);
    }
  }
  NAV_IMPORTS.set(sf, out);
  return out;
}

/**
 * `redirect()`, `notFound()` and their kin imported from next/navigation throw, so calling one ends
 * the request. A method of the same name does not: `NextResponse.redirect(url)` and
 * `Response.redirect(url)` build a response, which ends nothing unless it is returned (review cx14c).
 */
export function throwsNavigation(call: ts.CallExpression): boolean {
  const c = call.expression;
  const nav = navigationImports(call.getSourceFile());
  if (ts.isIdentifier(c)) return THROWING_NAV.test(nav.get(c.text) ?? "");
  return (
    ts.isPropertyAccessExpression(c) &&
    ts.isIdentifier(c.expression) &&
    nav.get(c.expression.text) === "*" &&
    THROWING_NAV.test(c.name.text)
  );
}

/** Does a statement stop the function (return, throw, or a Next.js redirect/notFound)? */
export function exitKind(stmt: ts.Node): "throw" | "return" | null {
  let kind: "throw" | "return" | null = null;
  walkOwn(stmt, (n) => {
    if (ts.isThrowStatement(n)) kind = "throw";
    else if (ts.isCallExpression(n) && throwsNavigation(n)) kind = "throw";
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
/**
 * `new Webhook(secret).verify(...)`, or `const wh = new Webhook(secret); wh.verify(...)`: the secret
 * is held by the receiver instead of being passed to the call.
 */
function receiverSecret(
  callee: ts.Expression,
  secretish: (e: ts.Expression) => boolean,
  builtFromSecret: ReadonlySet<string>,
): boolean {
  if (!ts.isPropertyAccessExpression(callee)) return false;
  const recv = callee.expression;
  if (ts.isNewExpression(recv)) return (recv.arguments ?? []).some(secretish);
  if (ts.isIdentifier(recv) && builtFromSecret.has(recv.text)) return true;
  return secretish(recv);
}

/** Locals of this function initialized with `new X(<secret>)`. */
function instancesBuiltFromSecret(
  body: ts.Node,
  secretish: (e: ts.Expression) => boolean,
): Set<string> {
  const out = new Set<string>();
  for (const d of collectNodes(body, ts.isVariableDeclaration)) {
    if (!d.initializer || !ts.isIdentifier(d.name) || !ts.isNewExpression(d.initializer)) continue;
    if ((d.initializer.arguments ?? []).some(secretish)) out.add(d.name.text);
  }
  return out;
}

/**
 * A verification that throws lands in a catch that ends the request: that is a gate even though the
 * call itself is a plain statement. Only used for calls that already look like a verification, so an
 * ordinary call inside a try/catch never becomes an authentication check.
 */
function gatesByThrow(node: ts.Node, fnBody: ts.Node): boolean {
  let child: ts.Node = node;
  let cur: ts.Node | undefined = node.parent;
  while (cur && cur !== fnBody && !isFunctionLikeNode(cur)) {
    if (ts.isTryStatement(cur) && cur.tryBlock === child && cur.catchClause) {
      return exitKind(cur.catchClause.block) !== null;
    }
    child = cur;
    cur = cur.parent;
  }
  return false;
}

export function secretChecksIn(fn: FunctionLike, sf: ts.SourceFile): SecretCheck[] {
  if (!fn.body) return [];
  const body = fn.body;
  const secrets = secretScopeFor(fn, sf);
  const secretish = (e: ts.Expression): boolean => isSecretish(e, secrets);
  const builtFromSecret = instancesBuiltFromSecret(body, secretish);
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
    // `new Webhook(process.env.SECRET).verify(payload, headers)`: the secret is on the receiver.
    const receiverHoldsSecret = verify && receiverSecret(n.expression, secretish, builtFromSecret);
    if (!receiverHoldsSecret && (secretArgs === 0 || secretArgs === n.arguments.length)) return;
    if ((verify && throwsOnBadCredential(n)) || gates(n, body) || gatesByThrow(n, body)) push(n);
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
  /(keyhash|tokenhash|hashedkey|hashedtoken|secrethash|apikey|apikeyhash|apitoken|accesstoken|sessiontoken|secret|token|sessioncode|invitecode|accesscode|sharecode)$/;

export function isCredentialColumn(column: string | null): boolean {
  return column !== null && CREDENTIAL_COLUMN.test(column.toLowerCase().replace(/_/g, ""));
}

/** WebAuthn assertion verifiers, by package: the signature is checked against a stored public key. */
const WEBAUTHN_VERIFIERS: ReadonlyArray<{ spec: string; name: string }> = [
  { spec: "@simplewebauthn/server", name: "verifyAuthenticationResponse" },
];

/** `!v.verified`, `!v?.verified`, `v.verified === false`, `v.verified !== true`. */
function deniesUnverified(cond: ts.Expression, name: string): boolean {
  const u = unwrap(cond);
  const isVerified = (e: ts.Expression): boolean => {
    const x = unwrap(e);
    if (!ts.isPropertyAccessExpression(x) || x.name.text !== "verified") return false;
    const recv = unwrap(x.expression);
    return ts.isIdentifier(recv) && recv.text === name;
  };
  if (ts.isPrefixUnaryExpression(u) && u.operator === ts.SyntaxKind.ExclamationToken) {
    return isVerified(u.operand);
  }
  if (ts.isBinaryExpression(u) && isVerified(u.left)) {
    const op = u.operatorToken.kind;
    const r = unwrap(u.right).kind;
    return (
      (op === ts.SyntaxKind.EqualsEqualsEqualsToken && r === ts.SyntaxKind.FalseKeyword) ||
      (op === ts.SyntaxKind.ExclamationEqualsEqualsToken && r === ts.SyntaxKind.TrueKeyword)
    );
  }
  return false;
}

/** How a statement always ends: its own `return`/`throw`, or one at the top level of its block. */
function alwaysExits(stmt: ts.Statement): "throw" | "return" | null {
  if (ts.isThrowStatement(stmt)) return "throw";
  if (ts.isReturnStatement(stmt)) return "return";
  if (
    ts.isExpressionStatement(stmt) &&
    ts.isCallExpression(unwrap(stmt.expression)) &&
    throwsNavigation(unwrap(stmt.expression) as ts.CallExpression)
  ) {
    return "throw";
  }
  if (!ts.isBlock(stmt)) return null;
  for (const s of stmt.statements) {
    const k = alwaysExits(s);
    if (k !== null) return k;
  }
  return null;
}

/** The statement runs code or changes `name`: a call, `new`, `await`, a tagged template, an assignment to it. */
function runsCodeOrAssigns(stmt: ts.Node, name: string): boolean {
  let hit = false;
  walkOwn(stmt, (n) => {
    if (hit) return;
    if (
      ts.isCallExpression(n) ||
      ts.isNewExpression(n) ||
      ts.isAwaitExpression(n) ||
      ts.isTaggedTemplateExpression(n) ||
      ts.isYieldExpression(n) ||
      ts.isDeleteExpression(n)
    ) {
      hit = true;
    } else if (
      ts.isBinaryExpression(n) &&
      n.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
      n.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
      identifiersIn(n.left).has(name)
    ) {
      hit = true;
    } else if (
      (ts.isPrefixUnaryExpression(n) || ts.isPostfixUnaryExpression(n)) &&
      (n.operator === ts.SyntaxKind.PlusPlusToken ||
        n.operator === ts.SyntaxKind.MinusMinusToken) &&
      identifiersIn(n.operand).has(name)
    ) {
      hit = true;
    }
  });
  return hit;
}

/**
 * Where an awaited verification sits: the statement of the function body that runs it, and the
 * statements between it and the rest of the body. Only two places count, both run unconditionally:
 *
 *   - a statement of the body itself (`const v = await verify…`);
 *   - a statement of the `try` block of a `try` of the body, whose `catch` always leaves the function
 *     (`let v; try { v = await verify… } catch { return 401 }`), so reaching the next statement means
 *     the verification returned.
 *
 * Anything nested in a condition, a loop or a `catch` is not counted.
 */
function verificationPlace(
  stmt: ts.Statement,
  top: readonly ts.Statement[],
  returnEndsRequest: boolean,
): { index: number; tail: readonly ts.Statement[] } | null {
  const index = top.indexOf(stmt);
  if (index >= 0) return { index, tail: [] };
  const block = stmt.parent;
  if (!ts.isBlock(block) || !ts.isTryStatement(block.parent)) return null;
  const t = block.parent;
  if (t.tryBlock !== block || t.finallyBlock) return null;
  // A catch that returns ends the request only when every caller checks what it returns: a helper
  // whose `return null` the handler ignores lets a malformed assertion through (review cx14b).
  const caught = t.catchClause ? alwaysExits(t.catchClause.block) : "throw";
  if (caught === null || (caught === "return" && !returnEndsRequest)) return null;
  const tIndex = top.indexOf(t);
  if (tIndex < 0) return null;
  return { index: tIndex, tail: block.statements.slice(block.statements.indexOf(stmt) + 1) };
}

/**
 * Some statement that runs before `stmt` can leave the function with a `return`: a statement of the
 * body before the verification's place, or one before it in the same `try` block.
 */
function returnsBefore(stmt: ts.Statement, top: readonly ts.Statement[], index: number): boolean {
  const before: ts.Node[] = [...top.slice(0, index)];
  const block = stmt.parent;
  if (ts.isBlock(block) && top.indexOf(stmt) < 0) {
    before.push(...block.statements.slice(0, block.statements.indexOf(stmt)));
  }
  let hit = false;
  for (const s of before) {
    walkOwn(s, (n) => {
      if (ts.isReturnStatement(n)) hit = true;
    });
  }
  return hit;
}

/**
 * The public key a verification checks the assertion against: `credential.publicKey` (v10 and
 * later) or `authenticator.credentialPublicKey` (before), as written in the options; the credential
 * object itself when it is not written out; null when there is none to see.
 */
function verifiedKey(call: ts.CallExpression): ts.Expression | null {
  const opts = call.arguments[0] ? unwrap(call.arguments[0]) : null;
  if (!opts || !ts.isObjectLiteralExpression(opts)) return null;
  const prop = (o: ts.ObjectLiteralExpression, name: string): ts.Expression | null => {
    for (const p of o.properties) {
      if (ts.isSpreadAssignment(p)) return null;
      const n =
        p.name && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)) ? p.name.text : null;
      if (n !== name) continue;
      if (ts.isPropertyAssignment(p)) return p.initializer;
      if (ts.isShorthandPropertyAssignment(p)) return p.name;
      return null;
    }
    return null;
  };
  for (const [holder, key] of [
    ["credential", "publicKey"],
    ["authenticator", "credentialPublicKey"],
  ] as const) {
    const h = prop(opts, holder);
    if (!h) continue;
    const u = unwrap(h);
    return ts.isObjectLiteralExpression(u) ? prop(u, key) : h;
  }
  return null;
}

/**
 * A passkey login: `verifyAuthenticationResponse(...)` of @simplewebauthn/server, awaited, and denied
 * by `if (!verification.verified) return/throw`. The assertion is checked against the credential's
 * public key, which must be the one stored for the account (`storedKey`, which the caller answers
 * from the rows it read and the request input it tracks): with a key the request supplies, the
 * caller signs with a key of their own (review cx14d). It then identifies an account, as an API key
 * looked up by its hash does.
 *
 * The denial counts only where it decides every request that goes on: it is a statement of the
 * function body (never inside another condition), it comes after the verification (see
 * verificationPlace), and nothing runs between the two. That says nothing about what runs before
 * the verification: a query there, in a branch that answers early, is not covered (review w2, the
 * same gap getUser() checks have). Where the caller ignores the result, no `return` may come before
 * the verification at all (review w1). A `return`
 * ends the request only when every caller up to the entry point checks the result
 * (`returnEndsRequest`); a `throw` always does, and so does `redirect()` of next/navigation, never a
 * `NextResponse.redirect()` that is not returned. A verification whose result nothing checks, or one
 * checked in some branch only, is not counted.
 */
export function webauthnChecksIn(
  fn: FunctionLike,
  imports: ReadonlyMap<string, { spec: string; imported: string }>,
  opts: { returnEndsRequest: boolean; storedKey: (key: ts.Expression) => boolean },
): ts.CallExpression[] {
  if (!fn.body || !ts.isBlock(fn.body)) return [];
  const body = fn.body;
  const top = body.statements;
  const local = new Set<string>();
  for (const [name, ref] of imports) {
    if (WEBAUTHN_VERIFIERS.some((v) => v.spec === ref.spec && v.name === ref.imported)) {
      local.add(name);
    }
  }
  if (local.size === 0) return [];
  const out: ts.CallExpression[] = [];
  walkOwn(body, (n) => {
    if (!ts.isCallExpression(n) || !ts.isIdentifier(n.expression)) return;
    if (!local.has(n.expression.text)) return;
    let cur: ts.Node = n.parent;
    while (ts.isParenthesizedExpression(cur)) cur = cur.parent;
    if (!ts.isAwaitExpression(cur)) return;
    const holder = cur.parent;
    let name: string | null = null;
    let stmt: ts.Statement | null = null;
    if (
      ts.isVariableDeclaration(holder) &&
      ts.isIdentifier(holder.name) &&
      holder.initializer === cur &&
      ts.isVariableDeclarationList(holder.parent) &&
      holder.parent.declarations.length === 1 &&
      ts.isVariableStatement(holder.parent.parent)
    ) {
      name = holder.name.text;
      stmt = holder.parent.parent;
    } else if (
      ts.isBinaryExpression(holder) &&
      holder.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      holder.right === cur &&
      ts.isIdentifier(holder.left) &&
      ts.isExpressionStatement(holder.parent)
    ) {
      name = holder.left.text;
      stmt = holder.parent;
    }
    if (name === null || stmt === null) return;
    const v = name;
    const key = verifiedKey(n);
    if (!key || !opts.storedKey(key)) return;
    const place = verificationPlace(stmt, top, opts.returnEndsRequest);
    if (!place) return;
    // Where the caller ignores what this function returns, a `return` before the verification lets
    // the request go on unverified (`if (!body.response) return null;` first thing, review w1).
    if (!opts.returnEndsRequest && returnsBefore(stmt, top, place.index)) return;
    // The first statement after the verification that denies an unverified assertion; everything
    // before it must run nothing (no query, no call) and leave the result alone.
    const between: ts.Statement[] = [...place.tail];
    let j = place.index + 1;
    for (; j < top.length; j++) {
      const s = top[j];
      if (s && ts.isIfStatement(s) && deniesUnverified(s.expression, v)) break;
      if (s) between.push(s);
    }
    const deny = top[j];
    if (!deny || !ts.isIfStatement(deny)) return;
    if (between.some((s) => runsCodeOrAssigns(s, v))) return;
    const exit = alwaysExits(deny.thenStatement);
    if (exit === null || (exit === "return" && !opts.returnEndsRequest)) return;
    out.push(n);
  });
  return out;
}
