import ts from "typescript";
import {
  type CallChain,
  type ChainSegment,
  collect,
  stringLiteralValue,
  unwrap,
  walk,
} from "./ast.js";
import type { QueryOperation, StorageAccess } from "./model.js";

/**
 * Supabase Storage object operations and the row operation each performs on `storage.objects`.
 * `getPublicUrl` is absent on purpose: it only formats a URL and touches no object.
 */
export const STORAGE_OPS: Readonly<Record<string, QueryOperation>> = {
  download: "select",
  list: "select",
  createSignedUrl: "select",
  createSignedUrls: "select",
  upload: "insert",
  createSignedUploadUrl: "insert",
  copy: "insert",
  update: "update",
  move: "update",
  remove: "delete",
};

/** move(from, to) and copy(from, to) take two object paths; everything else takes one (or one array). */
const TWO_PATHS = new Set(["move", "copy"]);

/** `const docs = supabase.storage.from("docs")`: a bucket handle bound to a name. */
export interface StorageBinding {
  clientRoot: ts.Expression;
  bucketArg: ts.Expression | undefined;
}

export interface StorageCall {
  /** The client expression before `.storage` (`supabase`, `createAdmin()`, `this.client`). */
  clientRoot: ts.Expression;
  bucketArg: ts.Expression | undefined;
  /** The object operation, or undefined for a bare bucket handle or an operation we do not model. */
  op: ChainSegment | undefined;
}

function isStorageRoot(e: ts.Expression): e is ts.PropertyAccessExpression {
  const u = unwrap(e);
  return ts.isPropertyAccessExpression(u) && u.name.text === "storage";
}

/** Bucket handles declared in a function body: `const bucket = client.storage.from("docs")`. */
export function storageBindingsIn(body: ts.Node): Map<string, StorageBinding> {
  const out = new Map<string, StorageBinding>();
  for (const decl of collect(body, ts.isVariableDeclaration)) {
    if (!decl.initializer || !ts.isIdentifier(decl.name)) continue;
    const init = unwrap(decl.initializer);
    if (!ts.isCallExpression(init) || !ts.isPropertyAccessExpression(init.expression)) continue;
    const callee = init.expression;
    if (callee.name.text !== "from" || !isStorageRoot(callee.expression)) continue;
    const root = unwrap(callee.expression) as ts.PropertyAccessExpression;
    out.set(decl.name.text, { clientRoot: root.expression, bucketArg: init.arguments[0] });
  }
  return out;
}

/**
 * Recognises `<client>.storage.from(bucket).<op>(…)` and `<handle>.<op>(…)` for a bound bucket handle.
 * Returns null when the chain is not a storage call at all; a storage chain whose operation is not an
 * object access (a bare handle, `getPublicUrl`) comes back with `op` undefined.
 */
export function storageCallOf(
  chain: CallChain,
  bound: ReadonlyMap<string, StorageBinding>,
): StorageCall | null {
  const root = unwrap(chain.root);
  const [first, second] = chain.segments;
  const known = (s: ChainSegment | undefined): ChainSegment | undefined =>
    s && STORAGE_OPS[s.name] !== undefined ? s : undefined;
  if (isStorageRoot(root) && first?.name === "from") {
    const r = unwrap(root) as ts.PropertyAccessExpression;
    return { clientRoot: r.expression, bucketArg: first.args[0], op: known(second) };
  }
  if (ts.isIdentifier(root) && first) {
    const b = bound.get(root.text);
    if (b) return { clientRoot: b.clientRoot, bucketArg: b.bucketArg, op: known(first) };
  }
  return null;
}

/** A bucket id from a literal or a string constant declared in the same file (`const BUCKET = "docs"`). */
export function bucketName(arg: ts.Expression | undefined, sf: ts.SourceFile): string | null {
  if (!arg) return null;
  const u = unwrap(arg);
  const lit = stringLiteralValue(u);
  if (lit !== null) return lit;
  if (!ts.isIdentifier(u)) return null;
  for (const d of collect(sf, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(d.name) || d.name.text !== u.text || !d.initializer) continue;
    const v = stringLiteralValue(unwrap(d.initializer));
    if (v !== null) return v;
  }
  return null;
}

/** Objects that carry the caller's identity: `user.id`, `session.user.id`, `claims.sub`, `profile.tenant_id`. */
const IDENTITY_OBJECT =
  /^(user|currentUser|authUser|sessionUser|session|claims|jwt|viewer|me|profile|member|membership|account|tenant|org|organization|workspace|team)$/i;
/** Fields that name an owner or tenant key even on an object we cannot place (`ctx.userId`, `row.tenant_id`). */
const OWNER_FIELD =
  /^(sub|uid|user_?id|owner_?id|tenant_?id|org_?id|organization_?id|workspace_?id|team_?id|account_?id)$/i;
/** Bare variables holding the caller's key, when they are not request input: `userId`, `tenantId`. */
const IDENTITY_VAR =
  /^(uid|user_?id|owner_?id|tenant_?id|org_?id|organization_?id|workspace_?id|team_?id|account_?id|current_?user_?id|caller_?id|viewer_?id)$/i;
/** Names that always mean request input, whatever the field after them. */
const INPUT_OBJECT = /^(params|searchParams|body|query|headers|cookies|formData)$/;

/**
 * Decides whether a storage path is tied to the caller: it embeds the session user's (or tenant's) id,
 * or it is checked against it (`path.startsWith(`${user.id}/`)`, `path.split("/")[0] === user.id`).
 * Syntactic and name-based, like the rest of the parser: it prefers a missed finding to a false one.
 */
export class CallerScope {
  private readonly scopedVars = new Set<string>();
  private readonly guarded = new Set<string>();

  constructor(
    body: ts.Node,
    private readonly inputNames: ReadonlySet<string>,
  ) {
    // Variables built from the caller's id, in source order: `const objectPath = `${user.id}/${name}``.
    for (const decl of collect(body, ts.isVariableDeclaration)) {
      if (!decl.initializer || !ts.isIdentifier(decl.name)) continue;
      if (this.refersToCaller(decl.initializer)) this.scopedVars.add(decl.name.text);
    }
    for (const call of collect(body, ts.isCallExpression)) {
      const callee = call.expression;
      if (!ts.isPropertyAccessExpression(callee) || callee.name.text !== "startsWith") continue;
      const target = unwrap(callee.expression);
      const arg = call.arguments[0];
      if (ts.isIdentifier(target) && arg && this.refersToCaller(arg)) this.guarded.add(target.text);
    }
    for (const bin of collect(body, ts.isBinaryExpression)) {
      const k = bin.operatorToken.kind;
      if (
        k !== ts.SyntaxKind.EqualsEqualsEqualsToken &&
        k !== ts.SyntaxKind.ExclamationEqualsEqualsToken &&
        k !== ts.SyntaxKind.EqualsEqualsToken &&
        k !== ts.SyntaxKind.ExclamationEqualsToken
      ) {
        continue;
      }
      for (const [side, other] of [
        [bin.left, bin.right],
        [bin.right, bin.left],
      ] as const) {
        const target = splitHead(side);
        if (target && this.refersToCaller(other)) this.guarded.add(target);
      }
    }
  }

  /** True when the expression embeds the caller's id (directly, or through a variable built from it). */
  refersToCaller(e: ts.Node): boolean {
    let hit = false;
    walk(e, (n) => {
      if (hit) return false;
      if (ts.isPropertyAccessExpression(n) && this.isIdentityAccess(n)) {
        hit = true;
        return false;
      }
      if (ts.isIdentifier(n)) {
        const parent = n.parent;
        if (parent && ts.isPropertyAccessExpression(parent) && parent.name === n) return undefined;
        if (this.scopedVars.has(n.text)) hit = true;
        else if (IDENTITY_VAR.test(n.text) && !this.inputNames.has(n.text)) hit = true;
      }
      return hit ? false : undefined;
    });
    return hit;
  }

  /** A path argument is covered when it embeds the caller's id or is an identifier checked against it. */
  covers(e: ts.Expression): boolean {
    const u = unwrap(e);
    return this.refersToCaller(u) || (ts.isIdentifier(u) && this.guarded.has(u.text));
  }

  private isIdentityAccess(pa: ts.PropertyAccessExpression): boolean {
    const field = pa.name.text;
    const names: string[] = [];
    let base: ts.Expression = unwrap(pa.expression);
    while (ts.isPropertyAccessExpression(base)) {
      names.push(base.name.text);
      base = unwrap(base.expression);
    }
    if (!ts.isIdentifier(base) || this.inputNames.has(base.text)) return false;
    names.push(base.text);
    if (names.some((n) => INPUT_OBJECT.test(n))) return false;
    if (OWNER_FIELD.test(field)) return true;
    return field === "id" && names.some((n) => IDENTITY_OBJECT.test(n));
  }
}

/** `path.split("/")[0]` -> `path`. */
function splitHead(e: ts.Expression): string | null {
  const u = unwrap(e);
  if (!ts.isElementAccessExpression(u)) return null;
  const idx = u.argumentExpression;
  if (!ts.isNumericLiteral(idx) || idx.text !== "0") return null;
  const call = unwrap(u.expression);
  if (!ts.isCallExpression(call) || !ts.isPropertyAccessExpression(call.expression)) return null;
  if (call.expression.name.text !== "split") return null;
  const target = unwrap(call.expression.expression);
  return ts.isIdentifier(target) ? target.text : null;
}

/** Describes the object path(s) of a storage call: where they come from and whether they are tied to the caller. */
export function storageAccessOf(
  op: ChainSegment,
  bucket: string | null,
  sf: ts.SourceFile,
  scope: CallerScope,
  derived: (e: ts.Expression) => boolean,
): StorageAccess {
  const pathArgs = op.args.slice(0, TWO_PATHS.has(op.name) ? 2 : 1);
  // Array literals (`remove([a, b])`) are judged element by element.
  const parts = pathArgs.flatMap((a) => {
    const u = unwrap(a);
    return ts.isArrayLiteralExpression(u) ? [...u.elements] : [a];
  });
  const tainted = parts.filter((p) => derived(p));
  const judged = tainted.length > 0 ? tainted : parts;
  return {
    bucket,
    op: op.name,
    pathText: pathArgs
      .map((a) => a.getText(sf))
      .join(", ")
      .replace(/\s+/g, " ")
      .slice(0, 200),
    pathInputDerived: tainted.length > 0,
    pathScopedToCaller: judged.length > 0 && judged.every((p) => scope.covers(p)),
  };
}
