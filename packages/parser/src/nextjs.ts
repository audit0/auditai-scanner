import ts from "typescript";
import { type ExportedFunction, exportedFunctions, topLevelFunctions, unwrap } from "./ast.js";
import { HTTP_METHODS, type HttpMethod } from "./model.js";

const ROUTE_FILE = /^(?:(.*?)\/)?(?:src\/)?app\/(.*?)\/?route\.(ts|tsx|js|jsx|mjs)$/;
const PAGE_FILE = /^(?:(.*?)\/)?(?:src\/)?app\/(.*?)\/?page\.(tsx|ts|jsx|js)$/;

function routePath(dir: string): string {
  const parts = dir
    .split("/")
    .filter((p) => p.length > 0 && !p.startsWith("(") && !p.startsWith("@"));
  return `/${parts.join("/")}`;
}

/** Directory of the Next.js app that owns `rel` (empty string for a root-level app), or null when `rel` is not an App Router file. */
export function appRootOf(rel: string): string | null {
  const m = /^(?:(.*?)\/)?(?:src\/)?app\//.exec(rel);
  if (!m) return null;
  const prefix = m[1] ?? "";
  // Never treat node_modules or another package's `app` inside a route path as an app root.
  return prefix;
}

/** Maps `app/api/invoices/[id]/route.ts` to `/api/invoices/[id]`. Route groups and parallel slots are dropped. */
export function routeFromFile(rel: string): string | null {
  const m = ROUTE_FILE.exec(rel);
  if (!m) return null;
  return routePath(m[2] ?? "");
}

/** Maps `app/invoices/[id]/page.tsx` to `/invoices/[id]`. */
export function pageFromFile(rel: string): string | null {
  const m = PAGE_FILE.exec(rel);
  if (!m) return null;
  return routePath(m[2] ?? "");
}

/**
 * The default export of a page file: `export default async function Page()`, an anonymous default
 * function, or `export default Page` referring to a top-level function.
 */
export function pageHandlerIn(sf: ts.SourceFile): ExportedFunction | null {
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt)) {
      const mods = ts.getModifiers(stmt) ?? [];
      if (mods.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword)) {
        return { name: stmt.name?.text ?? "Page", fn: stmt, node: stmt, exported: true };
      }
    } else if (ts.isExportAssignment(stmt) && !stmt.isExportEquals) {
      const e = unwrap(stmt.expression);
      if (ts.isIdentifier(e)) {
        const f = topLevelFunctions(sf).find((t) => t.name === e.text);
        if (f) return { ...f, exported: true };
      } else if (ts.isArrowFunction(e) || ts.isFunctionExpression(e)) {
        return { name: "Page", fn: e, node: stmt, exported: true };
      }
    }
  }
  return null;
}

export interface RouteExport {
  method: HttpMethod;
  exported: ExportedFunction;
}

export function routeHandlersIn(sf: ts.SourceFile): RouteExport[] {
  const out: RouteExport[] = [];
  for (const ex of exportedFunctions(sf)) {
    if ((HTTP_METHODS as readonly string[]).includes(ex.name)) {
      out.push({ method: ex.name as HttpMethod, exported: ex });
    }
  }
  return out;
}

/** File-level directive such as "use server" or "use client" as the first statement. */
export function fileDirective(sf: ts.SourceFile): string | null {
  const first = sf.statements[0];
  if (first && ts.isExpressionStatement(first) && ts.isStringLiteral(first.expression))
    return first.expression.text;
  return null;
}

export function isServerActionFile(sf: ts.SourceFile): boolean {
  return fileDirective(sf) === "use server";
}

export function isClientComponentFile(sf: ts.SourceFile): boolean {
  return fileDirective(sf) === "use client";
}
