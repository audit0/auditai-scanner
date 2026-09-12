import ts from "typescript";
import { boundNames, ownReturns, unwrap } from "./ast.js";

/**
 * Whole-input tracking for mass assignment. Taint says "this value came from the caller"; wholeness
 * says "this value IS the caller's object, every field of it". Only the second one is mass
 * assignment when it reaches insert/update/upsert: `{ id, chat_id: chatId, role: m.role }` is
 * built from tainted values but names its columns, so it is an allow-list.
 */
export interface WholeContext {
  /** An identifier bound to an entire request input object (body, form data, action argument). */
  wholeName(name: string): boolean;
  /** `req.json()`, `req.formData()` or `req.text()` on the incoming request. */
  requestBody(call: ts.CallExpression): boolean;
  /** An identifier holding the incoming Request object itself. */
  requestName(name: string): boolean;
  /**
   * The expression is a schema this project declares that keeps only the fields it names, so
   * `schema.parse(body)` is an allow-list. False for a schema we cannot resolve: an unknown
   * `schema.parse(...)` has to stay whole, because it may keep every key the caller sent.
   */
  strippingSchema(e: ts.Expression): boolean;
}

/** Array methods whose result holds the receiver's own elements, unchanged. */
const ELEMENT_PRESERVING = new Set([
  "filter",
  "slice",
  "concat",
  "sort",
  "reverse",
  "flat",
  "find",
  "findLast",
  "at",
  "toSorted",
  "toReversed",
]);
/** Array methods whose result is whatever the callback builds from each element. */
const RESHAPING = new Set(["map", "flatMap"]);

const LOGICAL = new Set([
  ts.SyntaxKind.QuestionQuestionToken,
  ts.SyntaxKind.BarBarToken,
  ts.SyntaxKind.AmpersandAmpersandToken,
]);

/**
 * A parse through a schema this project declares: `levelSchema.parse(input)`,
 * `levelSchema.safeParse(input).data`. An object schema keeps only the fields it names, so the
 * result is an allow-list the developer wrote, not the caller's object. The schema has to be
 * resolvable (see `WholeContext.strippingSchema`): an unknown `schema.parse(...)` stays whole.
 */
const SCHEMA_PARSE = /^(parse|safeParse|parseAsync|safeParseAsync)$/;

function isSchemaParse(call: ts.CallExpression, cx: WholeContext): boolean {
  const callee = call.expression;
  if (!ts.isPropertyAccessExpression(callee) || !SCHEMA_PARSE.test(callee.name.text)) return false;
  const recv = callee.expression;
  if (isWholeInput(recv, cx)) return false;
  return cx.strippingSchema(recv);
}

/** Does `e` evaluate to an entire request input object, written without an allow-list of fields? */
export function isWholeInput(e: ts.Expression, cx: WholeContext): boolean {
  const u = unwrap(e);
  if (ts.isIdentifier(u)) return cx.wholeName(u.text);
  // A nested object of the caller's input (`body.profile`) is still theirs entirely — but
  // `parsed.data` of a schema parse is the fields the schema declares.
  if (ts.isPropertyAccessExpression(u) || ts.isElementAccessExpression(u)) {
    const inner = unwrap(u.expression);
    if (ts.isCallExpression(inner) && isSchemaParse(inner, cx)) return false;
    return isWholeInput(u.expression, cx);
  }
  if (ts.isObjectLiteralExpression(u)) {
    return u.properties.some((pr) => ts.isSpreadAssignment(pr) && isWholeInput(pr.expression, cx));
  }
  if (ts.isArrayLiteralExpression(u)) {
    return u.elements.some((el) => isWholeInput(ts.isSpreadElement(el) ? el.expression : el, cx));
  }
  if (ts.isConditionalExpression(u)) {
    return isWholeInput(u.whenTrue, cx) || isWholeInput(u.whenFalse, cx);
  }
  if (ts.isBinaryExpression(u) && LOGICAL.has(u.operatorToken.kind)) {
    return isWholeInput(u.left, cx) || isWholeInput(u.right, cx);
  }
  if (ts.isCallExpression(u)) return isWholeCall(u, cx);
  return false;
}

function isWholeCall(call: ts.CallExpression, cx: WholeContext): boolean {
  if (cx.requestBody(call)) return true;
  if (isSchemaParse(call, cx)) return false;
  const callee = call.expression;
  if (ts.isPropertyAccessExpression(callee)) {
    const method = callee.name.text;
    const receiverWhole = isWholeInput(callee.expression, cx);
    if (RESHAPING.has(method)) return callbackKeepsWhole(call.arguments[0], receiverWhole, cx);
    if (ELEMENT_PRESERVING.has(method) && receiverWhole) return true;
  }
  // A helper or built-in handed the whole input returns it: `parseBody(req)`, `Object.fromEntries(formData)`.
  return call.arguments.some((a) => {
    const ua = unwrap(a);
    return isWholeInput(a, cx) || (ts.isIdentifier(ua) && cx.requestName(ua.text));
  });
}

/**
 * `rows.map(cb)` keeps the caller's objects only when the callback returns the element itself or
 * spreads it (`{ ...row, owner }`). A callback that returns a literal of explicit fields is an allow-list.
 * A callback we cannot see (`rows.map(normalize)`) keeps whatever the receiver was.
 */
function callbackKeepsWhole(
  cb: ts.Expression | undefined,
  receiverWhole: boolean,
  cx: WholeContext,
): boolean {
  if (!cb) return false;
  const f = unwrap(cb);
  if (!ts.isArrowFunction(f) && !ts.isFunctionExpression(f)) return receiverWhole;
  const element = f.parameters[0];
  const elementNames = new Set(receiverWhole && element ? boundNames(element.name) : []);
  const inner: WholeContext = {
    wholeName: (n) => elementNames.has(n) || cx.wholeName(n),
    requestBody: cx.requestBody,
    requestName: cx.requestName,
    strippingSchema: cx.strippingSchema,
  };
  return ownReturns(f).some((r) => isWholeInput(r, inner));
}

function propertyKey(name: ts.PropertyName | ts.BindingName): string | null {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
  return null;
}

/**
 * Names of one parameter that receive an entire request input object from the argument at the call
 * site. `save({ chatId, messages })` called with `save({ chatId: id, messages: body.messages })` binds
 * `messages` whole and `chatId` not, property by property.
 */
export function wholeParamNames(
  param: ts.BindingName,
  arg: ts.Expression | undefined,
  cx: WholeContext,
): string[] {
  if (!arg) return [];
  const u = unwrap(arg);
  if (
    ts.isObjectBindingPattern(param) &&
    ts.isObjectLiteralExpression(u) &&
    !u.properties.some(ts.isSpreadAssignment)
  ) {
    const out: string[] = [];
    for (const el of param.elements) {
      if (el.dotDotDotToken) continue;
      const key = propertyKey(el.propertyName ?? el.name);
      const prop = u.properties.find((pr) => pr.name && propertyKey(pr.name) === key);
      const value =
        prop && ts.isPropertyAssignment(prop)
          ? prop.initializer
          : prop && ts.isShorthandPropertyAssignment(prop)
            ? prop.name
            : undefined;
      if (value && isWholeInput(value, cx)) out.push(...boundNames(el.name));
    }
    return out;
  }
  return isWholeInput(arg, cx) ? boundNames(param) : [];
}
