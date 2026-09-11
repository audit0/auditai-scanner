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

export type FunctionLike =
  | ts.FunctionDeclaration
  | ts.ArrowFunction
  | ts.FunctionExpression
  | ts.MethodDeclaration;

export interface TopLevelFunction {
  name: string;
  fn: FunctionLike;
  node: ts.Node;
  exported: boolean;
  /** Callee text when the function is passed to a wrapper: `export const x = enhanceAction(async () => {})`. */
  wrapper?: string;
}

export type ExportedFunction = TopLevelFunction;

function hasExportModifier(node: ts.Node): boolean {
  const mods = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
  return mods?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
}

/** The function behind a variable initializer: a literal, or the first function argument of a wrapper call. */
export function functionOfInitializer(
  init: ts.Expression,
  sf: ts.SourceFile,
): { fn: FunctionLike; wrapper?: string } | null {
  const u = unwrap(init);
  if (ts.isArrowFunction(u) || ts.isFunctionExpression(u)) return { fn: u };
  if (ts.isCallExpression(u)) {
    for (const a of u.arguments) {
      const ua = unwrap(a);
      if (ts.isArrowFunction(ua) || ts.isFunctionExpression(ua)) {
        return { fn: ua, wrapper: u.expression.getText(sf).replace(/\s+/g, "") };
      }
    }
  }
  return null;
}

/** Every top-level function: declarations, `const x = () => {}` and wrapped `const x = wrap(() => {})`. */
export function topLevelFunctions(sf: ts.SourceFile): TopLevelFunction[] {
  const out: TopLevelFunction[] = [];
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name) {
      out.push({ name: stmt.name.text, fn: stmt, node: stmt, exported: hasExportModifier(stmt) });
    } else if (ts.isVariableStatement(stmt)) {
      const exported = hasExportModifier(stmt);
      for (const d of stmt.declarationList.declarations) {
        if (!ts.isIdentifier(d.name) || !d.initializer) continue;
        const f = functionOfInitializer(d.initializer, sf);
        if (!f) continue;
        out.push(
          f.wrapper === undefined
            ? { name: d.name.text, fn: f.fn, node: d, exported }
            : { name: d.name.text, fn: f.fn, node: d, exported, wrapper: f.wrapper },
        );
      }
    }
  }
  return out;
}

/** Top-level exported functions, including wrapped ones. */
export function exportedFunctions(sf: ts.SourceFile): ExportedFunction[] {
  return topLevelFunctions(sf).filter((f) => f.exported);
}

export interface ClassInfo {
  name: string;
  node: ts.ClassDeclaration;
  exported: boolean;
  /** Constructor parameter names by position. */
  ctorParams: string[];
  /** `this.<prop>` -> constructor parameter index (parameter properties and `this.x = x` assignments). */
  propFromParam: Map<string, number>;
  methods: Map<string, ts.MethodDeclaration>;
}

/** Top-level classes with the constructor wiring needed to follow `this.client` back to a caller's argument. */
export function classesIn(sf: ts.SourceFile): ClassInfo[] {
  const out: ClassInfo[] = [];
  for (const stmt of sf.statements) {
    if (!ts.isClassDeclaration(stmt) || !stmt.name) continue;
    const ctorParams: string[] = [];
    const propFromParam = new Map<string, number>();
    const methods = new Map<string, ts.MethodDeclaration>();
    for (const member of stmt.members) {
      if (ts.isConstructorDeclaration(member)) {
        member.parameters.forEach((p, i) => {
          const name = ts.isIdentifier(p.name) ? p.name.text : `arg${i}`;
          ctorParams.push(name);
          const mods = ts.getModifiers(p) ?? [];
          if (
            mods.some(
              (m) =>
                m.kind === ts.SyntaxKind.PrivateKeyword ||
                m.kind === ts.SyntaxKind.PublicKeyword ||
                m.kind === ts.SyntaxKind.ProtectedKeyword ||
                m.kind === ts.SyntaxKind.ReadonlyKeyword,
            )
          ) {
            propFromParam.set(name, i);
          }
        });
        if (member.body) {
          for (const bin of collect(member.body, ts.isBinaryExpression)) {
            if (
              bin.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
              ts.isPropertyAccessExpression(bin.left) &&
              bin.left.expression.kind === ts.SyntaxKind.ThisKeyword &&
              ts.isIdentifier(bin.right)
            ) {
              const idx = ctorParams.indexOf(bin.right.text);
              if (idx >= 0) propFromParam.set(bin.left.name.text, idx);
            }
          }
        }
      } else if (ts.isMethodDeclaration(member) && ts.isIdentifier(member.name)) {
        methods.set(member.name.text, member);
      }
    }
    out.push({
      name: stmt.name.text,
      node: stmt,
      exported: hasExportModifier(stmt),
      ctorParams,
      propFromParam,
      methods,
    });
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

/** All variable names used inside an expression. Property names (`row.id`) and object keys are not variables. */
export function identifiersIn(node: ts.Node): Set<string> {
  const out = new Set<string>();
  walk(node, (n) => {
    if (!ts.isIdentifier(n)) return undefined;
    const parent = n.parent;
    if (parent && ts.isPropertyAccessExpression(parent) && parent.name === n) return undefined;
    if (parent && ts.isPropertyAssignment(parent) && parent.name === n) return undefined;
    out.add(n.text);
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
