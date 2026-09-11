import ts from "typescript";

export function parseSource(fileName: string, text: string): ts.SourceFile {
  const kind = fileName.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  return ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, kind);
}

export function lineOf(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
}

/** Depth-first walk. Return false from `visit` to skip a subtree. */
export function walk(node: ts.Node, visit: (n: ts.Node) => boolean | undefined): void {
  if (visit(node) === false) return;
  node.forEachChild((child) => {
    walk(child, visit);
  });
}

export function collect<T extends ts.Node>(root: ts.Node, pred: (n: ts.Node) => n is T): T[] {
  const out: T[] = [];
  walk(root, (n) => {
    if (pred(n)) out.push(n);
    return undefined;
  });
  return out;
}

export function stringLiteralValue(e: ts.Node | undefined): string | null {
  if (!e) return null;
  if (ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e)) return e.text;
  return null;
}

/** Unwraps await / parens / non-null / as-casts. */
export function unwrap(e: ts.Expression): ts.Expression {
  let cur: ts.Expression = e;
  for (;;) {
    if (
      ts.isAwaitExpression(cur) ||
      ts.isParenthesizedExpression(cur) ||
      ts.isNonNullExpression(cur) ||
      ts.isAsExpression(cur) ||
      ts.isTypeAssertionExpression(cur) ||
      ts.isSatisfiesExpression(cur)
    ) {
      cur = cur.expression;
    } else {
      return cur;
    }
  }
}

export interface ChainSegment {
  name: string;
  args: readonly ts.Expression[];
  node: ts.CallExpression;
}

export interface CallChain {
  root: ts.Expression;
  segments: ChainSegment[];
}

/** Flattens `root.a(x).b(y)` into the root expression plus segments in call order. */
export function flattenChain(call: ts.CallExpression): CallChain {
  const segments: ChainSegment[] = [];
  let expr: ts.Expression = call;
  for (;;) {
    expr = unwrap(expr);
    if (ts.isCallExpression(expr) && ts.isPropertyAccessExpression(expr.expression)) {
      segments.unshift({ name: expr.expression.name.text, args: expr.arguments, node: expr });
      expr = expr.expression.expression;
    } else {
      break;
    }
  }
  return { root: expr, segments };
}

/** True when the call is the last link of its chain (not itself the receiver of another call). */
export function isChainTail(call: ts.CallExpression): boolean {
  let p: ts.Node = call.parent;
  while (
    p &&
    (ts.isAwaitExpression(p) ||
      ts.isParenthesizedExpression(p) ||
      ts.isNonNullExpression(p) ||
      ts.isAsExpression(p))
  ) {
    p = p.parent;
  }
  if (p && ts.isPropertyAccessExpression(p) && p.parent && ts.isCallExpression(p.parent)) {
    return p.parent.expression !== p;
  }
  return true;
}

export type FunctionLike = ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression;

export interface ExportedFunction {
  name: string;
  fn: FunctionLike;
  node: ts.Node;
}

function hasExportModifier(node: ts.Node): boolean {
  const mods = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
  return mods?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
}

/** Top-level exported functions: `export async function X` and `export const X = () => {}`. */
export function exportedFunctions(sf: ts.SourceFile): ExportedFunction[] {
  const out: ExportedFunction[] = [];
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name && hasExportModifier(stmt)) {
      out.push({ name: stmt.name.text, fn: stmt, node: stmt });
    } else if (ts.isVariableStatement(stmt) && hasExportModifier(stmt)) {
      for (const d of stmt.declarationList.declarations) {
        if (ts.isIdentifier(d.name) && d.initializer) {
          const init = unwrap(d.initializer);
          if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) {
            out.push({ name: d.name.text, fn: init, node: d });
          }
        }
      }
    }
  }
  return out;
}

/** Names bound by a destructuring pattern or a plain identifier. */
export function boundNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  const out: string[] = [];
  for (const el of name.elements) {
    if (ts.isOmittedExpression(el)) continue;
    out.push(...boundNames(el.name));
  }
  return out;
}

/** All identifier names used inside an expression. */
export function identifiersIn(node: ts.Node): Set<string> {
  const out = new Set<string>();
  walk(node, (n) => {
    if (ts.isIdentifier(n)) out.add(n.text);
    return undefined;
  });
  return out;
}

const IGNORE_RE = /auditai:ignore(?:\s+([A-Za-z0-9_.*-]+))?(?:\s*(?:--|:)\s*(.*))?/;

export interface ParsedIgnore {
  ruleId: string;
  reason: string;
  line: number;
}

/** Finds `auditai:ignore` directives in the comments immediately before `pos` (or the file header when pos is 0). */
export function parseIgnoreDirectives(sf: ts.SourceFile, pos: number): ParsedIgnore[] {
  const out: ParsedIgnore[] = [];
  const ranges = ts.getLeadingCommentRanges(sf.text, pos) ?? [];
  for (const r of ranges) {
    const text = sf.text.slice(r.pos, r.end);
    const m = IGNORE_RE.exec(text);
    if (!m) continue;
    const reason = (m[2] ?? "").replace(/\*\/\s*$/, "").trim();
    out.push({
      ruleId: m[1] ?? "*",
      reason: reason || "(no reason given)",
      line: sf.getLineAndCharacterOfPosition(r.pos).line + 1,
    });
  }
  return out;
}

/** The top-level statement that contains `node` (for leading-comment lookup on exported declarations). */
export function enclosingStatement(node: ts.Node): ts.Node {
  let cur: ts.Node = node;
  while (cur.parent && !ts.isSourceFile(cur.parent)) cur = cur.parent;
  return cur;
}
