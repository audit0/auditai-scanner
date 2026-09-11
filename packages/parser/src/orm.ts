import ts from "typescript";
import { collect, unwrap } from "./ast.js";
import type { QueryOperation } from "./model.js";

/**
 * Drizzle and Prisma talk to Postgres directly: no PostgREST, no Supabase RLS unless the app sets the
 * authenticated role itself. For authorization purposes such a client behaves like the service role,
 * which is why both are classified as `direct_db`.
 */

export const DRIZZLE_TABLE_FNS = new Set(["pgTable", "mysqlTable", "sqliteTable"]);
const DRIZZLE_PREDICATES = new Set([
  "eq",
  "ne",
  "gt",
  "gte",
  "lt",
  "lte",
  "like",
  "ilike",
  "notIlike",
  "inArray",
  "notInArray",
  "isNull",
  "isNotNull",
  "between",
  "notBetween",
  "arrayContains",
  "arrayContained",
]);
const DRIZZLE_COMBINATORS = new Set(["and", "or", "not"]);
export const DRIZZLE_WRITE_OPS: Record<string, QueryOperation> = {
  insert: "insert",
  update: "update",
  delete: "delete",
};
export const DRIZZLE_QUERY_API = new Set(["findFirst", "findMany"]);
export const PRISMA_OPS: Record<string, QueryOperation> = {
  findUnique: "select",
  findUniqueOrThrow: "select",
  findFirst: "select",
  findFirstOrThrow: "select",
  findMany: "select",
  count: "select",
  aggregate: "select",
  groupBy: "select",
  create: "insert",
  createMany: "insert",
  update: "update",
  updateMany: "update",
  upsert: "upsert",
  delete: "delete",
  deleteMany: "delete",
};

/** `drizzle(pool, { schema })` from any drizzle-orm driver package. */
export function isDrizzleCall(call: ts.CallExpression): boolean {
  const c = call.expression;
  if (ts.isIdentifier(c)) return c.text === "drizzle";
  return ts.isPropertyAccessExpression(c) && c.name.text === "drizzle";
}

/** `new PrismaClient(...)`, also through a generated client re-export. */
export function isPrismaNew(e: ts.Expression): boolean {
  const u = unwrap(e);
  if (!ts.isNewExpression(u)) return false;
  const c = u.expression;
  if (ts.isIdentifier(c)) return c.text === "PrismaClient";
  return ts.isPropertyAccessExpression(c) && c.name.text === "PrismaClient";
}

/**
 * The operand that actually creates something in `globalThis.prisma ?? new PrismaClient()` or
 * `cached || drizzle(pool)`; other expressions come back unchanged.
 */
export function clientCreatingOperand(e: ts.Expression): ts.Expression {
  const u = unwrap(e);
  if (
    ts.isBinaryExpression(u) &&
    (u.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken ||
      u.operatorToken.kind === ts.SyntaxKind.BarBarToken)
  ) {
    for (const side of [u.right, u.left]) {
      const s = clientCreatingOperand(side);
      if (ts.isNewExpression(s) || ts.isCallExpression(s)) return s;
    }
  }
  return u;
}

/** One predicate of a where clause, ORM-agnostic. `value` is null for opaque SQL fragments. */
export interface OrmFilter {
  method: string;
  column: string | null;
  value: ts.Expression | null;
  text: string;
}

function columnName(e: ts.Expression | undefined): string | null {
  if (!e) return null;
  const u = unwrap(e);
  if (ts.isPropertyAccessExpression(u)) return u.name.text;
  if (ts.isIdentifier(u)) return u.text;
  return null;
}

/**
 * Flattens `and(eq(t.id, id), inArray(t.tenantId, ids))`, arrow-function where clauses of the
 * relational query API, and opaque `sql\`...\`` fragments into filters.
 */
export function drizzleFilters(expr: ts.Expression | undefined, sf: ts.SourceFile): OrmFilter[] {
  if (!expr) return [];
  const u = unwrap(expr);
  if (ts.isCallExpression(u)) {
    const callee = u.expression;
    const name = ts.isIdentifier(callee)
      ? callee.text
      : ts.isPropertyAccessExpression(callee)
        ? callee.name.text
        : "";
    if (DRIZZLE_COMBINATORS.has(name)) return u.arguments.flatMap((a) => drizzleFilters(a, sf));
    if (DRIZZLE_PREDICATES.has(name)) {
      return [
        {
          method: name,
          column: columnName(u.arguments[0]),
          value: u.arguments[1] ?? null,
          text: u.getText(sf),
        },
      ];
    }
  }
  if (ts.isArrowFunction(u) || ts.isFunctionExpression(u)) {
    if (ts.isBlock(u.body)) {
      const ret = collect(u.body, ts.isReturnStatement)[0]?.expression;
      return ret ? drizzleFilters(ret, sf) : [];
    }
    return drizzleFilters(u.body, sf);
  }
  if (ts.isTaggedTemplateExpression(u)) {
    return [{ method: "sql", column: null, value: u, text: u.getText(sf) }];
  }
  return [{ method: "where", column: null, value: u, text: u.getText(sf) }];
}

/** The initializer of `key` in an object literal argument, if any. */
export function objectProperty(obj: ts.Expression | undefined, key: string): ts.Expression | null {
  if (!obj) return null;
  const u = unwrap(obj);
  if (!ts.isObjectLiteralExpression(u)) return null;
  for (const pr of u.properties) {
    if (ts.isPropertyAssignment(pr) && pr.name.getText().replace(/['"]/g, "") === key) {
      return pr.initializer;
    }
    if (ts.isShorthandPropertyAssignment(pr) && pr.name.text === key) return pr.name;
  }
  return null;
}

/** `where: { id, tenantId: x, AND: [...] }` of a Prisma call → one filter per field. */
export function prismaWhereFilters(where: ts.Expression | null, sf: ts.SourceFile): OrmFilter[] {
  if (!where) return [];
  const u = unwrap(where);
  if (ts.isArrayLiteralExpression(u)) return u.elements.flatMap((e) => prismaWhereFilters(e, sf));
  if (!ts.isObjectLiteralExpression(u)) {
    return [{ method: "where", column: null, value: u, text: u.getText(sf) }];
  }
  const out: OrmFilter[] = [];
  for (const pr of u.properties) {
    if (ts.isShorthandPropertyAssignment(pr)) {
      out.push({ method: "eq", column: pr.name.text, value: pr.name, text: pr.getText(sf) });
    } else if (ts.isPropertyAssignment(pr)) {
      const key = pr.name.getText(sf).replace(/['"]/g, "");
      if (key === "AND" || key === "OR" || key === "NOT") {
        out.push(...prismaWhereFilters(pr.initializer, sf));
        continue;
      }
      const init = unwrap(pr.initializer);
      // `id: { in: ids }` / `{ equals: x }`: the operator object carries the value.
      if (ts.isObjectLiteralExpression(init)) {
        const opProp = init.properties.find(
          (q): q is ts.PropertyAssignment =>
            ts.isPropertyAssignment(q) &&
            /^(equals|in|notIn|contains|startsWith|endsWith|lt|lte|gt|gte|not)$/.test(
              q.name.getText(sf),
            ),
        );
        out.push({
          method: opProp ? opProp.name.getText(sf) : "eq",
          column: key,
          value: opProp ? opProp.initializer : init,
          text: pr.getText(sf),
        });
        continue;
      }
      out.push({ method: "eq", column: key, value: pr.initializer, text: pr.getText(sf) });
    }
  }
  return out;
}

/** `model Invoice { ... @@map("invoices") }` → accessor `invoice` → table `invoices` (default: the model name). */
export function parsePrismaSchema(text: string): Map<string, string> {
  const out = new Map<string, string>();
  const re = /model\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{([^}]*)\}/g;
  for (const m of text.matchAll(re)) {
    const model = m[1];
    const body = m[2] ?? "";
    if (!model) continue;
    const mapped = /@@map\(\s*"([^"]+)"\s*\)/.exec(body);
    const accessor = model.charAt(0).toLowerCase() + model.slice(1);
    out.set(accessor, mapped?.[1] ?? model);
  }
  return out;
}
