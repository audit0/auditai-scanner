import {
  groupEnd,
  groupInner,
  isPunct,
  isWord,
  splitTopLevelTokens,
  type Token,
} from "./sql-lexer.js";

/**
 * Column definitions, table constraints and type names from CREATE/ALTER TABLE token streams.
 * Names fold like Postgres (bare words lowercase, quoted identifiers verbatim); model keys are then
 * lowercased, matching `RlsTable.table` and `RlsTable.columns`.
 */

/** A possibly schema-qualified name; `next` is the index of the first token after it. */
export interface QualifiedName {
  schema: string | null;
  name: string;
  next: number;
}

/** The identifier a word or quoted-identifier token names, or null for any other token. */
export function identOf(t: Token | undefined): string | null {
  if (!t || (t.kind !== "word" && t.kind !== "ident")) return null;
  return t.value;
}

export function readQualifiedName(tokens: readonly Token[], from: number): QualifiedName | null {
  const first = identOf(tokens[from]);
  if (first === null || first === "") return null;
  const parts = [first];
  let i = from + 1;
  while (isPunct(tokens[i], ".")) {
    const part = identOf(tokens[i + 1]);
    if (part === null) break;
    parts.push(part);
    i += 2;
  }
  return {
    schema: parts.length > 1 ? (parts[parts.length - 2] ?? null) : null,
    name: parts[parts.length - 1] ?? first,
    next: i,
  };
}

export function isPublicSchema(schema: string | null): boolean {
  return schema === null || schema.toLowerCase() === "public";
}

/** Model key of a table or function: bare lowercase in `public`, `schema.name` (lowercase) elsewhere. */
export function qualifiedKey(q: { schema: string | null; name: string }): string {
  const name = q.name.toLowerCase();
  return isPublicSchema(q.schema) ? name : `${(q.schema ?? "").toLowerCase()}.${name}`;
}

/** The exact name Postgres stores, qualified like `qualifiedKey`. */
export function qualifiedExact(q: { schema: string | null; name: string }): string {
  return isPublicSchema(q.schema) ? q.name : `${q.schema ?? ""}.${q.name}`;
}

/** Lowercase identifiers of a comma-separated list such as `(a, "B", c)`. */
export function identList(tokens: readonly Token[]): string[] {
  const out: string[] = [];
  for (const part of splitTopLevelTokens(tokens)) {
    const name = identOf(part[0]);
    if (name !== null) out.push(name.toLowerCase());
  }
  return out;
}

const TYPE_ALIASES: Record<string, string> = {
  int: "integer",
  int4: "integer",
  serial: "integer",
  serial4: "integer",
  int8: "bigint",
  bigserial: "bigint",
  serial8: "bigint",
  int2: "smallint",
  smallserial: "smallint",
  serial2: "smallint",
  decimal: "numeric",
  float4: "real",
  float8: "double precision",
  float: "double precision",
  bool: "boolean",
  "character varying": "varchar",
  character: "char",
  bpchar: "char",
  "timestamp with time zone": "timestamptz",
  "timestamp without time zone": "timestamp",
  "time with time zone": "timetz",
  "time without time zone": "time",
  "bit varying": "varbit",
};
const SERIAL_TYPES = new Set([
  "serial",
  "serial4",
  "bigserial",
  "serial8",
  "smallserial",
  "serial2",
]);

/** Words that end a column's type and start its constraints. */
const COLUMN_CONSTRAINT_WORDS = new Set([
  "not",
  "null",
  "default",
  "primary",
  "references",
  "unique",
  "check",
  "constraint",
  "generated",
  "collate",
  "deferrable",
  "initially",
]);

/**
 * Lowercase canonical type with modifiers and array dimensions: `varchar(80)`, `numeric(10,2)`,
 * `timestamptz`, `text[]`. The schema of a qualified type is dropped (`public.status` -> `status`).
 */
export function normalizeType(tokens: readonly Token[]): { type: string; serial: boolean } {
  let parts: string[] = [];
  let mods = "";
  let dims = 0;
  let arrayWord = false;
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (!t) continue;
    if (isPunct(t, ".")) {
      parts = [];
    } else if (isPunct(t, "(")) {
      const end = groupEnd(tokens, i);
      if (mods === "") {
        mods = tokens
          .slice(i, end + 1)
          .map((x) => x.raw)
          .join("")
          .toLowerCase();
      }
      i = end;
    } else if (isPunct(t, "[")) {
      dims += 1;
      i = groupEnd(tokens, i);
    } else if (isWord(t, "array")) {
      arrayWord = true;
    } else if (t.kind === "word" || t.kind === "ident") {
      parts.push(t.value.toLowerCase());
    }
  }
  let base = parts.join(" ");
  if (base === "") return { type: "unknown", serial: false };
  const serial = SERIAL_TYPES.has(base);
  if (base.startsWith("interval")) base = "interval";
  if (base === "float" && mods !== "") {
    const p = Number.parseInt(mods.slice(1), 10);
    base = Number.isFinite(p) && p <= 24 ? "real" : "double precision";
    mods = "";
  }
  const canonical = TYPE_ALIASES[base] ?? base;
  const arrays = "[]".repeat(dims > 0 ? dims : arrayWord ? 1 : 0);
  return { type: `${canonical}${mods}${arrays}`, serial };
}

export interface ColumnDef {
  /** Lowercase key. */
  name: string;
  /** Folded identifier (quoted names keep their case). */
  sqlName: string;
  type: string;
  nullable: boolean;
  /** DEFAULT <non-null expression> or serial. */
  defaultExpr: boolean;
  identity: boolean;
  /** GENERATED ALWAYS AS (expr) STORED: never written by an insert. */
  generated: boolean;
  primaryKey: boolean;
  /** `column` is null when the REFERENCES clause omits it (the target's primary key). */
  references: { table: string; column: string | null } | null;
  /** Explicit `CONSTRAINT name` of the REFERENCES clause, lowercase. */
  fkName: string | null;
}

export interface ParsedReferences {
  table: string;
  columns: string[];
  next: number;
}

function skipReferentialActions(tokens: readonly Token[], from: number): number {
  let i = from;
  while (i < tokens.length) {
    if (isWord(tokens[i], "match")) {
      i += 2;
    } else if (
      isWord(tokens[i], "on") &&
      (isWord(tokens[i + 1], "delete") || isWord(tokens[i + 1], "update"))
    ) {
      i += 2;
      i += isWord(tokens[i], "no") || isWord(tokens[i], "set") ? 2 : 1;
      if (isPunct(tokens[i], "(")) i = groupEnd(tokens, i) + 1;
    } else {
      break;
    }
  }
  return i;
}

/** `t [(a, b)] [match ...] [on delete ...]` after the REFERENCES keyword. */
export function readReferences(tokens: readonly Token[], from: number): ParsedReferences | null {
  const q = readQualifiedName(tokens, from);
  if (!q) return null;
  let i = q.next;
  let columns: string[] = [];
  if (isPunct(tokens[i], "(")) {
    columns = identList(groupInner(tokens, i));
    i = groupEnd(tokens, i) + 1;
  }
  return { table: qualifiedKey(q), columns, next: skipReferentialActions(tokens, i) };
}

/** Skips a DEFAULT expression; `isNull` for `DEFAULT NULL`, which is the same as no default. */
function skipDefault(tokens: readonly Token[], from: number): { next: number; isNull: boolean } {
  let i = from;
  let first = true;
  while (i < tokens.length) {
    const t = tokens[i];
    if (isPunct(t, "(") || isPunct(t, "[")) {
      i = groupEnd(tokens, i) + 1;
    } else if (!first && t?.kind === "word" && COLUMN_CONSTRAINT_WORDS.has(t.value)) {
      break;
    } else {
      i += 1;
    }
    first = false;
  }
  const isNull =
    isWord(tokens[from], "null") && (i === from + 1 || isPunct(tokens[from + 1], "::"));
  return { next: i, isNull };
}

/** True when an expression (SET DEFAULT ...) is a bare NULL. */
export function isNullExpression(tokens: readonly Token[]): boolean {
  return isWord(tokens[0], "null") && (tokens.length === 1 || isPunct(tokens[1], "::"));
}

function readGenerated(
  tokens: readonly Token[],
  at: number,
): { identity: boolean; generated: boolean; next: number } {
  let j = at + 1;
  if (isWord(tokens[j], "always")) j += 1;
  else if (isWord(tokens[j], "by") && isWord(tokens[j + 1], "default")) j += 2;
  if (!isWord(tokens[j], "as")) return { identity: false, generated: false, next: j };
  j += 1;
  if (isWord(tokens[j], "identity")) {
    j += 1;
    if (isPunct(tokens[j], "(")) j = groupEnd(tokens, j) + 1;
    return { identity: true, generated: false, next: j };
  }
  if (isPunct(tokens[j], "(")) {
    j = groupEnd(tokens, j) + 1;
    if (isWord(tokens[j], "stored") || isWord(tokens[j], "virtual")) j += 1;
    return { identity: false, generated: true, next: j };
  }
  return { identity: false, generated: false, next: j };
}

/** `name type [constraints...]` from a CREATE TABLE body or ADD COLUMN. Null when there is no name. */
export function parseColumnDef(tokens: readonly Token[]): ColumnDef | null {
  const sqlName = identOf(tokens[0]);
  if (sqlName === null || sqlName === "") return null;
  let i = 1;
  while (i < tokens.length) {
    const t = tokens[i];
    if (isPunct(t, "(") || isPunct(t, "[")) {
      i = groupEnd(tokens, i) + 1;
      continue;
    }
    if (t?.kind === "word" && COLUMN_CONSTRAINT_WORDS.has(t.value)) break;
    i += 1;
  }
  const { type, serial } = normalizeType(tokens.slice(1, i));
  const col: ColumnDef = {
    name: sqlName.toLowerCase(),
    sqlName,
    type,
    nullable: !serial,
    defaultExpr: serial,
    identity: false,
    generated: false,
    primaryKey: false,
    references: null,
    fkName: null,
  };
  let constraintName: string | null = null;
  while (i < tokens.length) {
    const t = tokens[i];
    if (!t) break;
    if (t.kind !== "word") {
      i = isPunct(t, "(") || isPunct(t, "[") ? groupEnd(tokens, i) + 1 : i + 1;
      continue;
    }
    if (t.value === "constraint") {
      constraintName = identOf(tokens[i + 1])?.toLowerCase() ?? null;
      i += 2;
      continue;
    }
    const named = constraintName;
    constraintName = null;
    switch (t.value) {
      case "not":
        if (isWord(tokens[i + 1], "null")) {
          col.nullable = false;
          i += 2;
        } else i += 1;
        break;
      case "null":
        col.nullable = true;
        i += 1;
        break;
      case "primary":
        col.primaryKey = true;
        col.nullable = false;
        i += isWord(tokens[i + 1], "key") ? 2 : 1;
        break;
      case "default": {
        const d = skipDefault(tokens, i + 1);
        col.defaultExpr = !d.isNull;
        i = d.next;
        break;
      }
      case "generated": {
        const g = readGenerated(tokens, i);
        if (g.identity) {
          col.identity = true;
          col.nullable = false;
        }
        if (g.generated) col.generated = true;
        i = g.next;
        break;
      }
      case "references": {
        const r = readReferences(tokens, i + 1);
        if (r) {
          col.references = { table: r.table, column: r.columns[0] ?? null };
          col.fkName = named;
          i = r.next;
        } else i += 1;
        break;
      }
      case "collate": {
        const q = readQualifiedName(tokens, i + 1);
        i = q ? q.next : i + 1;
        break;
      }
      default:
        i += 1;
    }
  }
  return col;
}

/** First words of a CREATE TABLE element that make it a table constraint rather than a column. */
export const TABLE_CONSTRAINT_WORDS = new Set([
  "primary",
  "unique",
  "constraint",
  "foreign",
  "check",
  "exclude",
  "like",
]);

export type TableConstraint =
  | { kind: "primary"; name: string | null; columns: string[]; usingIndex: string | null }
  | { kind: "foreign"; name: string | null; columns: string[]; table: string; refColumns: string[] }
  | { kind: "other"; name: string | null };

/** `[CONSTRAINT n] PRIMARY KEY (...) | FOREIGN KEY (...) REFERENCES t (...) | UNIQUE ... | CHECK ...`. */
export function parseTableConstraint(tokens: readonly Token[]): TableConstraint {
  let i = 0;
  let name: string | null = null;
  if (isWord(tokens[0], "constraint")) {
    name = identOf(tokens[1])?.toLowerCase() ?? null;
    i = 2;
  }
  if (isWord(tokens[i], "primary")) {
    i += isWord(tokens[i + 1], "key") ? 2 : 1;
    if (isPunct(tokens[i], "(")) {
      return { kind: "primary", name, columns: identList(groupInner(tokens, i)), usingIndex: null };
    }
    const usingIndex =
      isWord(tokens[i], "using") && isWord(tokens[i + 1], "index")
        ? (identOf(tokens[i + 2])?.toLowerCase() ?? null)
        : null;
    return { kind: "primary", name, columns: [], usingIndex };
  }
  if (isWord(tokens[i], "foreign")) {
    i += isWord(tokens[i + 1], "key") ? 2 : 1;
    if (!isPunct(tokens[i], "(")) return { kind: "other", name };
    const columns = identList(groupInner(tokens, i));
    i = groupEnd(tokens, i) + 1;
    const r = isWord(tokens[i], "references") ? readReferences(tokens, i + 1) : null;
    if (!r) return { kind: "other", name };
    return { kind: "foreign", name, columns, table: r.table, refColumns: r.columns };
  }
  return { kind: "other", name };
}
