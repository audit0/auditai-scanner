import ts from "typescript";
import { unwrap, walk } from "./ast.js";
import { stoppedBefore } from "./guards.js";
import type { ImportRef } from "./supabase.js";

/**
 * Storage keys minted on the server for this request. A key whose last segment carries a random
 * token generated in the same request (`${folder}/${crypto.randomUUID()}.jpg`) names an object that
 * did not exist before the request: whatever else in it came from the caller, it cannot reach an
 * existing object of another user. That is a fact about the value, not about who wrote the code, so
 * it rests on the generator's module (node:crypto, uuid, nanoid) and on the shape of the key.
 *
 * supabase-js puts the key into the request URL unencoded, and URL parsing moves the goalposts
 * twice: it resolves `..` segments, and `?` or `#` ends the path. So the token only protects the key
 * when nothing after it can open a new segment (no `/` or `\`) and nothing the caller sends before
 * it can cut the path short (no `?` or `#`). Both are proved on the value, never assumed.
 */

/** What a name in the function being read stands for. */
export type Binding =
  /** A parameter of the function, and whether its caller bound a fresh key to it. */
  | { kind: "param"; fresh: boolean; reassigned: boolean }
  /** The only declaration of a local that is never reassigned. */
  | { kind: "local"; init: ts.Expression }
  /** A module-level const, of this module or imported from another one of this repository. */
  | { kind: "module"; init: ts.Expression }
  | { kind: "unknown" };

export interface KeyContext {
  /** The body of the function the expressions belong to. */
  body: ts.Node;
  resolve(name: string): Binding;
  /** Where an imported local comes from. */
  importOf(name: string): ImportRef | undefined;
  /** The value is derived from the caller's input (the parser's taint). */
  derived(e: ts.Expression): boolean;
  /** A helper of this repository whose every returned value is a fresh key. */
  helperReturnsFresh(call: ts.CallExpression): boolean;
}

const MAX_DEPTH = 8;
const NODE_CRYPTO = new Set(["crypto", "node:crypto"]);
/** Characters that open a new path segment once the key is in a URL. */
const SEPARATORS = "/\\";
/** Characters that end the URL path, leaving the rest of the key in the query or the fragment. */
const PATH_ENDS = "?#";
/** String methods whose result is the receiver's own text, whole. */
const TEXT_PRESERVING = new Set(["trim", "trimStart", "trimEnd", "toString", "toLowerCase"]);
/** String methods whose result only drops or re-cases characters of the receiver: no new ones. */
const NO_NEW_CHARS = new Set([
  "slice",
  "substring",
  "substr",
  "trim",
  "trimStart",
  "trimEnd",
  "toLowerCase",
  "toUpperCase",
]);

function hasAny(text: string, chars: string): boolean {
  for (const c of chars) if (text.includes(c)) return true;
  return false;
}

function numericAtLeast(e: ts.Expression | undefined, min: number): boolean {
  if (!e) return false;
  const u = unwrap(e);
  return ts.isNumericLiteral(u) && Number(u.text) >= min;
}

/** `crypto` as the Web Crypto global or Node's module. */
function isCryptoObject(e: ts.Expression, cx: KeyContext): boolean {
  const u = unwrap(e);
  if (ts.isIdentifier(u)) {
    if (u.text !== "crypto" || cx.resolve(u.text).kind !== "unknown") return false;
    const imp = cx.importOf(u.text);
    return imp === undefined || NODE_CRYPTO.has(imp.spec);
  }
  if (ts.isPropertyAccessExpression(u) && u.name.text === "crypto") {
    const base = unwrap(u.expression);
    return ts.isIdentifier(base) && /^(globalThis|window|self)$/.test(base.text);
  }
  return false;
}

/** `randomBytes(16)` / `crypto.randomBytes(16)` from node:crypto: at least 8 random bytes. */
function isRandomBytes(e: ts.Expression, cx: KeyContext): boolean {
  const u = unwrap(e);
  if (!ts.isCallExpression(u) || !numericAtLeast(u.arguments[0], 8)) return false;
  const callee = unwrap(u.expression);
  if (ts.isIdentifier(callee)) {
    const imp = cx.importOf(callee.text);
    return imp !== undefined && NODE_CRYPTO.has(imp.spec) && imp.imported === "randomBytes";
  }
  return (
    ts.isPropertyAccessExpression(callee) &&
    callee.name.text === "randomBytes" &&
    isCryptoObject(callee.expression, cx)
  );
}

/**
 * A call that returns a random token no one can predict: `crypto.randomUUID()`, `randomUUID()` and
 * `randomBytes(n).toString("hex" | "base64url")` from node:crypto, `v4()` from uuid, `nanoid()`.
 * Recognised by the module the function comes from, never by its local name.
 */
export function isRandomTokenCall(call: ts.CallExpression, cx: KeyContext): boolean {
  const callee = unwrap(call.expression);
  if (ts.isIdentifier(callee)) {
    const imp = cx.importOf(callee.text);
    if (!imp || cx.resolve(callee.text).kind !== "unknown") return false;
    if (NODE_CRYPTO.has(imp.spec)) return imp.imported === "randomUUID";
    if (imp.spec === "uuid") return imp.imported === "v4";
    if (imp.spec === "nanoid") {
      return (
        imp.imported === "nanoid" &&
        (call.arguments.length === 0 || numericAtLeast(call.arguments[0], 16))
      );
    }
    return false;
  }
  if (!ts.isPropertyAccessExpression(callee)) return false;
  const method = callee.name.text;
  if (method === "randomUUID") return isCryptoObject(callee.expression, cx);
  if (method === "v4") {
    const base = unwrap(callee.expression);
    const imp = ts.isIdentifier(base) ? cx.importOf(base.text) : undefined;
    return imp?.spec === "uuid" && (imp.imported === "*" || imp.imported === "default");
  }
  if (method === "toString") {
    const enc = call.arguments[0] ? unwrap(call.arguments[0]) : undefined;
    // Plain base64 has `/` in its alphabet.
    return (
      enc !== undefined &&
      ts.isStringLiteralLike(enc) &&
      (enc.text === "hex" || enc.text === "base64url") &&
      isRandomBytes(callee.expression, cx)
    );
  }
  return false;
}

/** The value of `a ? b : c`, `a ?? b`, `a || b`: each branch it can take. */
function branches(e: ts.Expression): ts.Expression[] {
  const u = unwrap(e);
  if (ts.isConditionalExpression(u)) return [...branches(u.whenTrue), ...branches(u.whenFalse)];
  if (
    ts.isBinaryExpression(u) &&
    (u.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken ||
      u.operatorToken.kind === ts.SyntaxKind.BarBarToken)
  ) {
    return [...branches(u.left), ...branches(u.right)];
  }
  return [u];
}

/** `a + b + c` -> [a, b, c]; anything else -> null. */
function concatOperands(e: ts.Expression): ts.Expression[] | null {
  const u = unwrap(e);
  if (!ts.isBinaryExpression(u) || u.operatorToken.kind !== ts.SyntaxKind.PlusToken) return null;
  return [...(concatOperands(u.left) ?? [u.left]), ...(concatOperands(u.right) ?? [u.right])];
}

/** One piece of a key: literal text, or an expression whose value is spliced in. */
type Piece = { text: string } | { expr: ts.Expression };

function piecesOf(e: ts.Expression): Piece[] | null {
  const u = unwrap(e);
  if (ts.isTemplateExpression(u)) {
    const out: Piece[] = [{ text: u.head.text }];
    for (const span of u.templateSpans) {
      out.push({ expr: span.expression }, { text: span.literal.text });
    }
    return out;
  }
  const ops = concatOperands(u);
  if (!ops) return null;
  return ops.map((o) => {
    const x = unwrap(o);
    return ts.isStringLiteralLike(x) ? { text: x.text } : { expr: o };
  });
}

/**
 * The value always carries a token minted in this request in its last segment: nothing after the
 * token can open a new segment, and nothing the caller sends before it can end the URL path.
 */
export function isFreshKey(e: ts.Expression, cx: KeyContext, depth = 0): boolean {
  if (depth > MAX_DEPTH) return false;
  const bs = branches(e);
  if (bs.length > 1) return bs.every((b) => isFreshKey(b, cx, depth + 1));
  const u = unwrap(e);
  if (ts.isIdentifier(u)) {
    const b = cx.resolve(u.text);
    if (b.kind === "param") return b.fresh && !b.reassigned;
    // A module-level token is minted once per process and shared by every request: not fresh.
    return b.kind === "local" && isFreshKey(b.init, cx, depth + 1);
  }
  if (ts.isCallExpression(u)) {
    if (isRandomTokenCall(u, cx)) return true;
    const callee = unwrap(u.expression);
    if (ts.isPropertyAccessExpression(callee) && TEXT_PRESERVING.has(callee.name.text)) {
      return u.arguments.length === 0 && isFreshKey(callee.expression, cx, depth + 1);
    }
    if (ts.isIdentifier(callee) && callee.text === "String" && u.arguments.length === 1) {
      const [arg] = u.arguments;
      return arg !== undefined && isFreshKey(arg, cx, depth + 1);
    }
    return cx.helperReturnsFresh(u);
  }
  const pieces = piecesOf(u);
  if (!pieces) return false;
  let token = -1;
  pieces.forEach((pc, i) => {
    if ("expr" in pc && isFreshKey(pc.expr, cx, depth + 1)) token = i;
  });
  if (token < 0) return false;
  const before = pieces.slice(0, token);
  const after = pieces.slice(token + 1);
  return (
    before.every((pc) =>
      "text" in pc
        ? !hasAny(pc.text, PATH_ENDS)
        : !cx.derived(pc.expr) || excludes(pc.expr, PATH_ENDS, cx, depth + 1),
    ) &&
    after.every((pc) =>
      "text" in pc ? !hasAny(pc.text, SEPARATORS) : excludes(pc.expr, SEPARATORS, cx, depth + 1),
    )
  );
}

/**
 * The value can never contain any of `chars`, whatever the caller sent: a literal without them, a
 * number, a random token, a value stripped to an allow-list (`ext.replace(/[^a-z0-9]/g, "")`), an
 * entry of a constant table whose entries are all such literals (`EXT_BY_MIME[mime]`), or a name
 * that an allow-list pattern (`if (!UUID.test(id)) return …`) checked before this use.
 */
export function excludes(e: ts.Expression, chars: string, cx: KeyContext, depth = 0): boolean {
  if (depth > MAX_DEPTH) return false;
  const bs = branches(e);
  if (bs.length > 1) return bs.every((b) => excludes(b, chars, cx, depth + 1));
  const u = unwrap(e);
  if (ts.isStringLiteralLike(u)) return !hasAny(u.text, chars);
  if (ts.isNumericLiteral(u)) return true;
  if (ts.isIdentifier(u)) {
    const b = cx.resolve(u.text);
    if ((b.kind === "local" || b.kind === "module") && excludes(b.init, chars, cx, depth + 1)) {
      return true;
    }
    const checkable = b.kind === "local" || (b.kind === "param" && !b.reassigned);
    return checkable && allowListedBefore(u, chars, cx);
  }
  const pieces = piecesOf(u);
  if (pieces) {
    return pieces.every((pc) =>
      "text" in pc ? !hasAny(pc.text, chars) : excludes(pc.expr, chars, cx, depth + 1),
    );
  }
  if (ts.isCallExpression(u)) {
    if (isRandomTokenCall(u, cx)) return true;
    const callee = unwrap(u.expression);
    if (!ts.isPropertyAccessExpression(callee)) return false;
    const method = callee.name.text;
    if (
      method === "now" &&
      ts.isIdentifier(callee.expression) &&
      callee.expression.text === "Date"
    ) {
      return u.arguments.length === 0;
    }
    if (method === "replace" || method === "replaceAll") return stripsTo(u, chars);
    return NO_NEW_CHARS.has(method) && excludes(callee.expression, chars, cx, depth + 1);
  }
  if (ts.isElementAccessExpression(u)) return tableExcludes(u.expression, null, chars, cx);
  if (ts.isPropertyAccessExpression(u)) {
    const inner = unwrap(u.expression);
    return (
      ts.isElementAccessExpression(inner) && tableExcludes(inner.expression, u.name.text, chars, cx)
    );
  }
  return false;
}

function propertyName(name: ts.PropertyName): string | null {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)) {
    return name.text;
  }
  return null;
}

/**
 * `TABLE[key]` (field null) or `TABLE[key].field` over a constant object literal: every entry (or
 * that field of every entry) is a literal without `chars`. A key the caller picks can only select
 * one of them, or a member of Object.prototype, whose text holds none of `/ \ ? #` either.
 */
function tableExcludes(
  t: ts.Expression,
  field: string | null,
  chars: string,
  cx: KeyContext,
): boolean {
  const base = unwrap(t);
  if (!ts.isIdentifier(base)) return false;
  const b = cx.resolve(base.text);
  if (b.kind !== "local" && b.kind !== "module") return false;
  const obj = unwrap(b.init);
  if (!ts.isObjectLiteralExpression(obj) || obj.properties.length === 0) return false;
  const safeLiteral = (e: ts.Expression): boolean => {
    const v = unwrap(e);
    return ts.isStringLiteralLike(v) && !hasAny(v.text, chars);
  };
  return obj.properties.every((pr) => {
    if (!ts.isPropertyAssignment(pr)) return false;
    if (field === null) return safeLiteral(pr.initializer);
    const entry = unwrap(pr.initializer);
    if (!ts.isObjectLiteralExpression(entry)) return false;
    return entry.properties.every((q) => {
      if (!ts.isPropertyAssignment(q)) return false;
      const name = propertyName(q.name);
      if (name === null) return false;
      return name !== field || safeLiteral(q.initializer);
    });
  });
}

/** `x.replace(/[^a-z0-9]/g, "")`: every character outside an allow-list without `chars` is dropped. */
function stripsTo(call: ts.CallExpression, chars: string): boolean {
  const [re, rep] = call.arguments;
  if (!re || !rep) return false;
  const r = unwrap(re);
  const s = unwrap(rep);
  // `$&` and friends would put the matched (disallowed) character back.
  if (!ts.isStringLiteralLike(s) || hasAny(s.text, chars) || s.text.includes("$")) return false;
  return ts.isRegularExpressionLiteral(r) && isStrippingPattern(r.text, chars);
}

function regexParts(text: string): { body: string; flags: string } | null {
  const end = text.lastIndexOf("/");
  if (!text.startsWith("/") || end <= 0) return null;
  return { body: text.slice(1, end), flags: text.slice(end + 1) };
}

/**
 * The inside of a character class (without the brackets) keeps no character of `chars`. Ranges are
 * limited to a-z, A-Z and 0-9; escapes to \w, \d, \s and punctuation (`\x2f` and `/` spell a
 * slash, so letter escapes other than those three are refused).
 */
export function classKeepsNone(body: string, chars: string): boolean {
  let i = 0;
  while (i < body.length) {
    const c = body.charAt(i);
    const escaped = c === "\\";
    const atom = escaped ? body.slice(i, i + 2) : c;
    const next = i + atom.length;
    // `x-y` is a range whenever a character follows the dash; `[\!-~]` spans `/`, `?` and `#`.
    if (body.charAt(next) === "-" && next + 1 < body.length) {
      const hi = body.charAt(next + 1);
      if (escaped || hi === "\\" || !isPlainRange(c, hi)) return false;
      i = next + 2;
      continue;
    }
    if (escaped) {
      const n = atom.charAt(1);
      if (n === "" || chars.includes(n)) return false;
      if (/[A-Za-z0-9]/.test(n) && !/[wds]/.test(n)) return false;
    } else if (chars.includes(c)) {
      return false;
    }
    i = next;
  }
  return true;
}

function isPlainRange(lo: string, hi: string): boolean {
  if (lo > hi) return false;
  return (
    (/[a-z]/.test(lo) && /[a-z]/.test(hi)) ||
    (/[A-Z]/.test(lo) && /[A-Z]/.test(hi)) ||
    (/[0-9]/.test(lo) && /[0-9]/.test(hi))
  );
}

/**
 * `/[^<allowed>]/g` (optionally `+` or `*` after the class): a global negated class whose allowed
 * characters include none of `chars`, so `replace(re, "")` leaves none of them.
 */
export function isStrippingPattern(text: string, chars: string): boolean {
  const parts = regexParts(text);
  if (!parts) return false;
  const m = /^\[\^((?:\\.|[^\]\\])*)\][+*]?$/.exec(parts.body);
  if (!m || !parts.flags.includes("g") || parts.flags.includes("v")) return false;
  return classKeepsNone(m[1] ?? "", chars);
}

/**
 * An allow-list pattern: anchored at both ends (`^…$`, no `m` flag), no `.`, no negated class and
 * no alternation outside a group, and every character it can match is outside `chars`. A string
 * that passes `test` can then hold none of them.
 */
export function isAllowListPattern(text: string, chars: string): boolean {
  const parts = regexParts(text);
  if (!parts) return false;
  const { body, flags } = parts;
  if (flags.includes("m") || flags.includes("v")) return false;
  if (!body.startsWith("^") || !body.endsWith("$") || body.endsWith("\\$")) return false;
  let depth = 0;
  let i = 1;
  const last = body.length - 1;
  while (i < last) {
    const c = body.charAt(i);
    if (c === "\\") {
      const n = body.charAt(i + 1);
      if (n === "" || chars.includes(n)) return false;
      if (/[A-Za-z0-9]/.test(n) && !/[wdsbB]/.test(n)) return false;
      i += 2;
      continue;
    }
    if (c === "[") {
      const close = classEnd(body, i);
      if (close < 0 || body.charAt(i + 1) === "^") return false;
      if (!classKeepsNone(body.slice(i + 1, close), chars)) return false;
      i = close + 1;
      continue;
    }
    if (c === ".") return false;
    if (c === "|" && depth === 0) return false;
    if (c === "(") depth += 1;
    else if (c === ")") depth -= 1;
    else if (c === "?" && body.charAt(i - 1) === "(") {
      // `(?:`, `(?=`, `(?!`, `(?<name>`: group syntax, not a character.
    } else if (!"*+?{},^$".includes(c) && !/[0-9]/.test(c) && chars.includes(c)) {
      return false;
    }
    i += 1;
  }
  return depth === 0;
}

/** Index of the `]` closing the class that opens at `open`, or -1. */
function classEnd(body: string, open: number): number {
  let i = open + 1;
  if (body.charAt(i) === "^") i += 1;
  if (body.charAt(i) === "]") i += 1;
  while (i < body.length) {
    const c = body.charAt(i);
    if (c === "\\") {
      i += 2;
      continue;
    }
    if (c === "]") return i;
    i += 1;
  }
  return -1;
}

/** The regex literal behind `RE` in `RE.test(x)`: inline, or a const of this function or module. */
function patternOf(e: ts.Expression, cx: KeyContext): string | null {
  const u = unwrap(e);
  if (ts.isRegularExpressionLiteral(u)) return u.text;
  if (!ts.isIdentifier(u)) return null;
  const b = cx.resolve(u.text);
  if (b.kind !== "local" && b.kind !== "module") return null;
  const init = unwrap(b.init);
  return ts.isRegularExpressionLiteral(init) ? init.text : null;
}

/** `!RE.test(name)` as the condition, or one of its `||` operands. */
function rejectsUnless(cond: ts.Expression, name: string, chars: string, cx: KeyContext): boolean {
  const u = unwrap(cond);
  if (ts.isBinaryExpression(u) && u.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
    return rejectsUnless(u.left, name, chars, cx) || rejectsUnless(u.right, name, chars, cx);
  }
  if (!ts.isPrefixUnaryExpression(u) || u.operator !== ts.SyntaxKind.ExclamationToken) return false;
  const call = unwrap(u.operand);
  if (!ts.isCallExpression(call) || call.arguments.length !== 1) return false;
  const callee = unwrap(call.expression);
  if (!ts.isPropertyAccessExpression(callee) || callee.name.text !== "test") return false;
  const arg = call.arguments[0] ? unwrap(call.arguments[0]) : undefined;
  if (!arg || !ts.isIdentifier(arg) || arg.text !== name) return false;
  const pattern = patternOf(callee.expression, cx);
  return pattern !== null && isAllowListPattern(pattern, chars);
}

/**
 * The name was checked against an allow-list before this use, on every path to it: an `if
 * (!RE.test(name)) return|throw …` dominates the use (see stoppedBefore).
 */
function allowListedBefore(use: ts.Identifier, chars: string, cx: KeyContext): boolean {
  return stoppedBefore(use, cx.body, (stop) => rejectsUnless(stop.expression, use.text, chars, cx));
}

/**
 * Names assigned anywhere in a function body, nested closures included (`x = …`, `x += …`, `x++`,
 * `({ path: x } = o)`, `[x] = a`, `for (x of list)`): their value at a use is not the one the
 * declaration or the caller gave them.
 */
export function reassignedIn(body: ts.Node): Set<string> {
  const out = new Set<string>();
  walk(body, (n) => {
    if (
      ts.isBinaryExpression(n) &&
      n.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
      n.operatorToken.kind <= ts.SyntaxKind.LastAssignment
    ) {
      assignmentTargets(n.left, out);
    } else if (
      (ts.isPrefixUnaryExpression(n) || ts.isPostfixUnaryExpression(n)) &&
      (n.operator === ts.SyntaxKind.PlusPlusToken || n.operator === ts.SyntaxKind.MinusMinusToken)
    ) {
      const op = unwrap(n.operand);
      if (ts.isIdentifier(op)) out.add(op.text);
    } else if (
      (ts.isForOfStatement(n) || ts.isForInStatement(n)) &&
      !ts.isVariableDeclarationList(n.initializer)
    ) {
      // `for (key of list)` / `for ({ path: key } of list)`: each turn assigns the existing name.
      assignmentTargets(n.initializer, out);
    }
    return undefined;
  });
  return out;
}

/**
 * The names an assignment target writes: `x`, and every name inside a destructuring pattern
 * written as a literal (`{ path: x }`, `{ x }`, `[x, ...rest]`, `{ a: [x = 1] }`). A property
 * target (`o.x = …`) writes no name.
 */
function assignmentTargets(target: ts.Expression, out: Set<string>): void {
  const t = unwrap(target);
  if (ts.isIdentifier(t)) {
    out.add(t.text);
  } else if (ts.isBinaryExpression(t) && t.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
    // A default inside a pattern: `{ path: x = "a" }`, `[x = 1]`.
    assignmentTargets(t.left, out);
  } else if (ts.isSpreadElement(t)) {
    assignmentTargets(t.expression, out);
  } else if (ts.isArrayLiteralExpression(t)) {
    for (const el of t.elements) assignmentTargets(el, out);
  } else if (ts.isObjectLiteralExpression(t)) {
    for (const pr of t.properties) {
      if (ts.isPropertyAssignment(pr)) assignmentTargets(pr.initializer, out);
      else if (ts.isShorthandPropertyAssignment(pr)) out.add(pr.name.text);
      else if (ts.isSpreadAssignment(pr)) assignmentTargets(pr.expression, out);
    }
  }
}
