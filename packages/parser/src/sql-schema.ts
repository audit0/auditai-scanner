import type { ColumnInfo, RlsTable, SqlFunctionInfo, StorageBucket } from "./model.js";
import {
  type ColumnDef,
  identList,
  identOf,
  isNullExpression,
  normalizeType,
  parseColumnDef,
  parseTableConstraint,
  qualifiedExact,
  qualifiedKey,
  readQualifiedName,
  TABLE_CONSTRAINT_WORDS,
  type TableConstraint,
} from "./sql-columns.js";
import {
  applyAlterFunction,
  applyCreateFunction,
  applyDefaultPrivileges,
  applyDropFunction,
  applyGrantRevoke,
  type FunctionRegistry,
  finishFunctions,
  newFunctionRegistry,
} from "./sql-functions.js";
import {
  findWord,
  groupEnd,
  groupInner,
  isPunct,
  isWord,
  type SqlStatement,
  splitSqlStatements,
  splitTopLevelTokens,
  type Token,
} from "./sql-lexer.js";
import {
  applyStorageStatement,
  type BucketRegistry,
  finishBuckets,
  newBucketRegistry,
} from "./sql-storage.js";

/**
 * Schema knowledge from migration SQL, applied statement by statement in file order so that later
 * statements override earlier ones: CREATE/ALTER/DROP TABLE, enums, functions and privileges,
 * storage buckets. Enough to seed two tenants automatically and to judge `supabase.rpc()` targets.
 */

interface ColumnState {
  name: string;
  sqlName: string;
  type: string;
  nullable: boolean;
  defaultExpr: boolean;
  identity: boolean;
  generated: boolean;
  /** `column` stays null only until the statement that added it resolves the target's primary key. */
  references: { table: string; column: string | null } | null;
  /** Lowercase name of the FOREIGN KEY constraint behind `references` (Postgres default naming). */
  fkName: string | null;
}

interface TableMeta {
  columns: ColumnState[];
  pk: string[];
  /** Defined by CREATE TABLE (not only mentioned by a policy or ALTER TABLE). */
  created: boolean;
}

export interface SqlSchemaState {
  tables: Map<string, RlsTable>;
  meta: Map<string, TableMeta>;
  /** Unique index name -> columns, for `ADD CONSTRAINT ... PRIMARY KEY USING INDEX` (Supabase CLI diff output). */
  uniqueIndexes: Map<string, string[]>;
  enums: Map<string, string[]>;
  functions: FunctionRegistry;
  buckets: BucketRegistry;
}

export interface SqlSchemaExtras {
  enums: Record<string, string[]>;
  sqlFunctions: SqlFunctionInfo[];
  storageBuckets: StorageBucket[];
}

/** Side state per table map, so `parseSqlForRls(rel, text, into)` keeps its signature across files. */
const STATES = new WeakMap<Map<string, RlsTable>, SqlSchemaState>();

export function schemaStateFor(tables: Map<string, RlsTable>): SqlSchemaState {
  let state = STATES.get(tables);
  if (!state) {
    state = {
      tables,
      meta: new Map(),
      uniqueIndexes: new Map(),
      enums: new Map(),
      functions: newFunctionRegistry(),
      buckets: newBucketRegistry(),
    };
    STATES.set(tables, state);
  }
  return state;
}

export function ensureTable(
  state: SqlSchemaState,
  key: string,
  file: string,
  line: number,
): RlsTable {
  let t = state.tables.get(key);
  if (!t) {
    t = {
      table: key,
      rlsEnabled: false,
      policies: [],
      policyDetails: [],
      columns: [],
      columnInfo: [],
      location: { file, line },
    };
    state.tables.set(key, t);
  }
  return t;
}

function bareName(key: string): string {
  const dot = key.lastIndexOf(".");
  return dot >= 0 ? key.slice(dot + 1) : key;
}

function schemaOfKey(key: string): string | null {
  const dot = key.lastIndexOf(".");
  return dot >= 0 ? key.slice(0, dot) : null;
}

function fromInfo(info: ColumnInfo): ColumnState {
  return {
    name: info.name,
    sqlName: info.sqlName ?? info.name,
    type: info.type,
    nullable: info.nullable,
    defaultExpr: info.hasDefault,
    identity: false,
    generated: false,
    references: info.references ? { ...info.references } : null,
    fkName: null,
  };
}

/** Column state of a table; tables built outside this module start from their `columns`. */
function metaOf(state: SqlSchemaState, key: string): TableMeta {
  let meta = state.meta.get(key);
  if (!meta) {
    const t = state.tables.get(key);
    const infos = t?.columnInfo ?? [];
    const columns = (t?.columns ?? []).map((name, i) => {
      const info = infos[i];
      return info && info.name === name
        ? fromInfo(info)
        : fromInfo({ name, type: "unknown", nullable: true, hasDefault: false, references: null });
    });
    meta = { columns, pk: [], created: false };
    state.meta.set(key, meta);
  }
  return meta;
}

function toInfo(c: ColumnState): ColumnInfo {
  const info: ColumnInfo = {
    name: c.name,
    type: c.type,
    nullable: c.nullable,
    hasDefault: c.defaultExpr || c.identity || c.generated,
    references: c.references
      ? { table: c.references.table, column: c.references.column ?? "id" }
      : null,
  };
  if (c.sqlName !== c.name) info.sqlName = c.sqlName;
  return info;
}

/** Writes the column state back to the RlsTable (`columns` and `columnInfo` stay index-aligned). */
function sync(state: SqlSchemaState, key: string): void {
  const t = state.tables.get(key);
  const meta = state.meta.get(key);
  if (!t || !meta) return;
  t.columns = meta.columns.map((c) => c.name);
  t.columnInfo = meta.columns.map(toInfo);
}

function findColumn(meta: TableMeta, name: string): ColumnState | undefined {
  return meta.columns.find((c) => c.name === name);
}

function pkOf(state: SqlSchemaState, table: string): string[] {
  if (table === "auth.users") return ["id"];
  return state.meta.get(table)?.pk ?? [];
}

/** An omitted REFERENCES column list means the target's primary key; "id" when it is unknown. */
function resolveRefs(state: SqlSchemaState, meta: TableMeta): void {
  for (const col of meta.columns) {
    if (col.references && col.references.column === null) {
      col.references.column = pkOf(state, col.references.table)[0] ?? "id";
    }
  }
}

/** Foreign keys into a dropped table or column disappear with it (CASCADE, or the migration fails). */
function clearRefsTo(state: SqlSchemaState, table: string, column?: string): void {
  for (const [key, meta] of state.meta) {
    let touched = false;
    for (const col of meta.columns) {
      const r = col.references;
      if (!r || r.table !== table || (column !== undefined && r.column !== column)) continue;
      col.references = null;
      col.fkName = null;
      touched = true;
    }
    if (touched) sync(state, key);
  }
}

function renameRefs(
  state: SqlSchemaState,
  fromTable: string,
  toTable: string,
  fromColumn?: string,
  toColumn?: string,
): void {
  for (const [key, meta] of state.meta) {
    let touched = false;
    for (const col of meta.columns) {
      const r = col.references;
      if (!r || r.table !== fromTable) continue;
      if (fromColumn !== undefined && r.column !== fromColumn) continue;
      col.references = { table: toTable, column: toColumn ?? r.column };
      touched = true;
    }
    if (touched) sync(state, key);
  }
}

function addColumn(meta: TableMeta, key: string, def: ColumnDef): void {
  const col: ColumnState = {
    name: def.name,
    sqlName: def.sqlName,
    type: def.type,
    nullable: def.nullable,
    defaultExpr: def.defaultExpr,
    identity: def.identity,
    generated: def.generated,
    references: def.references ? { ...def.references } : null,
    fkName: def.references ? (def.fkName ?? `${bareName(key)}_${def.name}_fkey`) : null,
  };
  const idx = meta.columns.findIndex((c) => c.name === col.name);
  if (idx >= 0) meta.columns[idx] = col;
  else meta.columns.push(col);
  if (def.primaryKey) meta.pk = [def.name];
}

function applyConstraint(
  state: SqlSchemaState,
  key: string,
  meta: TableMeta,
  c: TableConstraint,
): void {
  if (c.kind === "primary") {
    const cols =
      c.columns.length > 0
        ? c.columns
        : c.usingIndex !== null
          ? (state.uniqueIndexes.get(c.usingIndex) ?? [])
          : [];
    if (cols.length === 0) return;
    meta.pk = cols;
    for (const name of cols) {
      const col = findColumn(meta, name);
      if (col) col.nullable = false;
    }
  } else if (c.kind === "foreign") {
    const targets = c.refColumns.length > 0 ? c.refColumns : pkOf(state, c.table);
    const fkName = c.name ?? `${bareName(key)}_${c.columns.join("_")}_fkey`;
    c.columns.forEach((name, idx) => {
      const col = findColumn(meta, name);
      if (!col) return;
      col.references = { table: c.table, column: targets[idx] ?? null };
      col.fkName = fkName;
    });
  }
}

function createTable(state: SqlSchemaState, stmt: SqlStatement, file: string): void {
  const tk = stmt.tokens;
  let i = 1;
  if (isWord(tk[i], "unlogged")) i += 1;
  if (!isWord(tk[i], "table")) return;
  i += 1;
  let ifNotExists = false;
  if (isWord(tk[i], "if") && isWord(tk[i + 1], "not") && isWord(tk[i + 2], "exists")) {
    ifNotExists = true;
    i += 3;
  }
  const q = readQualifiedName(tk, i);
  if (!q || !isPunct(tk[q.next], "(")) return;
  const key = qualifiedKey(q);
  // CREATE TABLE IF NOT EXISTS on an existing table is a no-op in Postgres.
  if (ifNotExists && state.meta.get(key)?.created) return;
  const t = ensureTable(state, key, file, stmt.line);
  const exact = qualifiedExact(q);
  if (exact !== key) t.sqlName = exact;
  else delete t.sqlName;
  const meta: TableMeta = { columns: [], pk: [], created: true };
  state.meta.set(key, meta);
  const constraints: TableConstraint[] = [];
  for (const part of splitTopLevelTokens(groupInner(tk, q.next))) {
    const first = part[0];
    if (first?.kind === "word" && TABLE_CONSTRAINT_WORDS.has(first.value)) {
      // LIKE other_table copies columns we cannot see here; it is skipped.
      if (first.value !== "like") constraints.push(parseTableConstraint(part));
      continue;
    }
    const def = parseColumnDef(part);
    if (def) addColumn(meta, key, def);
  }
  // Primary keys first, so a self-reference without a column list resolves to this table's key.
  for (const c of constraints) if (c.kind === "primary") applyConstraint(state, key, meta, c);
  for (const c of constraints) if (c.kind !== "primary") applyConstraint(state, key, meta, c);
  resolveRefs(state, meta);
  sync(state, key);
}

function alterAdd(state: SqlSchemaState, key: string, meta: TableMeta, action: Token[]): void {
  const w1 = action[1];
  if (w1?.kind === "word" && TABLE_CONSTRAINT_WORDS.has(w1.value) && w1.value !== "like") {
    applyConstraint(state, key, meta, parseTableConstraint(action.slice(1)));
    return;
  }
  let j = 1;
  if (isWord(action[j], "column")) j += 1;
  if (isWord(action[j], "if") && isWord(action[j + 1], "not") && isWord(action[j + 2], "exists")) {
    j += 3;
  }
  const def = parseColumnDef(action.slice(j));
  // An existing column stays as it is: IF NOT EXISTS makes it a no-op, without it Postgres fails.
  if (!def || findColumn(meta, def.name)) return;
  addColumn(meta, key, def);
}

function alterDrop(state: SqlSchemaState, key: string, meta: TableMeta, action: Token[]): void {
  let j = 1;
  if (isWord(action[j], "constraint")) {
    j += 1;
    if (isWord(action[j], "if") && isWord(action[j + 1], "exists")) j += 2;
    const name = identOf(action[j])?.toLowerCase();
    if (!name) return;
    for (const col of meta.columns) {
      if (col.fkName !== name) continue;
      col.references = null;
      col.fkName = null;
    }
    return;
  }
  if (isWord(action[j], "column")) j += 1;
  if (isWord(action[j], "if") && isWord(action[j + 1], "exists")) j += 2;
  const name = identOf(action[j])?.toLowerCase();
  if (!name) return;
  meta.columns = meta.columns.filter((c) => c.name !== name);
  meta.pk = meta.pk.filter((c) => c !== name);
  clearRefsTo(state, key, name);
}

function alterColumn(meta: TableMeta, action: Token[]): void {
  let j = 1;
  if (isWord(action[j], "constraint")) return;
  if (isWord(action[j], "column")) j += 1;
  const name = identOf(action[j])?.toLowerCase();
  const col = name === undefined ? undefined : findColumn(meta, name);
  if (!col) return;
  j += 1;
  const a = action[j];
  const b = action[j + 1];
  const c = action[j + 2];
  if (isWord(a, "set") && isWord(b, "not") && isWord(c, "null")) col.nullable = false;
  else if (isWord(a, "drop") && isWord(b, "not") && isWord(c, "null")) col.nullable = true;
  else if (isWord(a, "set") && isWord(b, "default")) {
    col.defaultExpr = !isNullExpression(action.slice(j + 2));
  } else if (isWord(a, "drop") && isWord(b, "default")) col.defaultExpr = false;
  else if (isWord(a, "type") || (isWord(a, "set") && isWord(b, "data") && isWord(c, "type"))) {
    const from = isWord(a, "type") ? j + 1 : j + 3;
    let end = from;
    while (
      end < action.length &&
      !isWord(action[end], "collate") &&
      !isWord(action[end], "using")
    ) {
      end =
        isPunct(action[end], "(") || isPunct(action[end], "[")
          ? groupEnd(action, end) + 1
          : end + 1;
    }
    col.type = normalizeType(action.slice(from, end)).type;
  } else if (isWord(a, "add") && isWord(b, "generated")) {
    col.identity = true;
    col.nullable = false;
  } else if (isWord(a, "drop") && isWord(b, "identity")) col.identity = false;
  else if (isWord(a, "drop") && isWord(b, "expression")) col.generated = false;
}

/** RENAME TO / RENAME CONSTRAINT / RENAME [COLUMN]; returns the (possibly new) table key. */
function alterRename(state: SqlSchemaState, key: string, meta: TableMeta, action: Token[]): string {
  if (isWord(action[1], "to")) {
    const name = identOf(action[2]);
    const t = state.tables.get(key);
    if (!name || !t) return key;
    const q = { schema: schemaOfKey(key), name };
    const next = qualifiedKey(q);
    state.tables.delete(key);
    t.table = next;
    const exact = qualifiedExact(q);
    if (exact !== next) t.sqlName = exact;
    else delete t.sqlName;
    state.tables.set(next, t);
    state.meta.delete(key);
    state.meta.set(next, meta);
    renameRefs(state, key, next);
    return next;
  }
  if (isWord(action[1], "constraint")) {
    const from = identOf(action[2])?.toLowerCase();
    const to = isWord(action[3], "to") ? identOf(action[4])?.toLowerCase() : undefined;
    if (from === undefined || to === undefined) return key;
    for (const col of meta.columns) if (col.fkName === from) col.fkName = to;
    return key;
  }
  let j = 1;
  if (isWord(action[j], "column")) j += 1;
  const from = identOf(action[j]);
  const to = isWord(action[j + 1], "to") ? identOf(action[j + 2]) : null;
  const col = from === null ? undefined : findColumn(meta, from.toLowerCase());
  if (!col || to === null) return key;
  const old = col.name;
  col.name = to.toLowerCase();
  col.sqlName = to;
  meta.pk = meta.pk.map((c) => (c === old ? col.name : c));
  sync(state, key);
  renameRefs(state, key, key, old, col.name);
  return key;
}

function alterAction(
  state: SqlSchemaState,
  key: string,
  action: Token[],
  file: string,
  line: number,
  schemaOnly: boolean,
): string {
  const w0 = action[0];
  if (
    (isWord(w0, "enable") || isWord(w0, "disable")) &&
    isWord(action[1], "row") &&
    isWord(action[2], "level") &&
    isWord(action[3], "security")
  ) {
    if (!schemaOnly) ensureTable(state, key, file, line).rlsEnabled = isWord(w0, "enable");
    return key;
  }
  // Column changes only apply to tables the migrations define.
  if (!state.tables.has(key)) return key;
  const meta = metaOf(state, key);
  if (isWord(w0, "rename")) return alterRename(state, key, meta, action);
  if (isWord(w0, "add")) alterAdd(state, key, meta, action);
  else if (isWord(w0, "drop")) alterDrop(state, key, meta, action);
  else if (isWord(w0, "alter")) alterColumn(meta, action);
  else return key;
  resolveRefs(state, meta);
  sync(state, key);
  return key;
}

/** ALTER TABLE [IF EXISTS] [ONLY] name action [, action ...]. `schemaOnly` skips RLS switches (DO blocks). */
function alterTable(
  state: SqlSchemaState,
  stmt: SqlStatement,
  file: string,
  schemaOnly: boolean,
): void {
  const tk = stmt.tokens;
  let i = 2;
  for (;;) {
    if (isWord(tk[i], "if") && isWord(tk[i + 1], "exists")) i += 2;
    else if (isWord(tk[i], "only")) i += 1;
    else break;
  }
  const q = readQualifiedName(tk, i);
  if (!q) return;
  let key = qualifiedKey(q);
  i = q.next;
  if (tk[i]?.raw === "*") i += 1;
  for (const action of splitTopLevelTokens(tk.slice(i))) {
    key = alterAction(state, key, action, file, stmt.line, schemaOnly);
  }
}

function dropTable(state: SqlSchemaState, stmt: SqlStatement): void {
  const tk = stmt.tokens;
  let i = 2;
  if (isWord(tk[i], "if") && isWord(tk[i + 1], "exists")) i += 2;
  for (const part of splitTopLevelTokens(tk.slice(i))) {
    const q = readQualifiedName(part, 0);
    if (!q) continue;
    const key = qualifiedKey(q);
    state.tables.delete(key);
    state.meta.delete(key);
    clearRefsTo(state, key);
  }
}

/** CREATE UNIQUE INDEX name ON t (cols): remembered for PRIMARY KEY USING INDEX. */
function createUniqueIndex(state: SqlSchemaState, stmt: SqlStatement): void {
  const tk = stmt.tokens;
  if (!isWord(tk[1], "unique") || !isWord(tk[2], "index")) return;
  const on = findWord(tk, 3, "on");
  const nameTok = tk[on - 1];
  if (on < 4 || !nameTok || ["index", "concurrently", "exists"].some((w) => isWord(nameTok, w))) {
    return;
  }
  const name = identOf(nameTok);
  const open = tk.findIndex((t, j) => j > on && isPunct(t, "("));
  if (name === null || open < 0) return;
  state.uniqueIndexes.set(name.toLowerCase(), identList(groupInner(tk, open)));
}

/** Enum keys are bare lowercase type names (schema dropped), matching `ColumnInfo.type`. */
function createType(state: SqlSchemaState, stmt: SqlStatement): void {
  const tk = stmt.tokens;
  const q = readQualifiedName(tk, 2);
  if (!q || !isWord(tk[q.next], "as") || !isWord(tk[q.next + 1], "enum")) return;
  if (!isPunct(tk[q.next + 2], "(")) return;
  const labels = groupInner(tk, q.next + 2)
    .filter((t) => t.kind === "string")
    .map((t) => t.value);
  state.enums.set(q.name.toLowerCase(), labels);
}

function retypeColumns(state: SqlSchemaState, from: string, to: string): void {
  for (const [key, meta] of state.meta) {
    let touched = false;
    for (const col of meta.columns) {
      if (col.type === from || col.type.startsWith(`${from}[`)) {
        col.type = to + col.type.slice(from.length);
        touched = true;
      }
    }
    if (touched) sync(state, key);
  }
}

/** ALTER TYPE e ADD VALUE [IF NOT EXISTS] 'x' [BEFORE|AFTER 'y'] | RENAME VALUE 'a' TO 'b' | RENAME TO f. */
function alterType(state: SqlSchemaState, stmt: SqlStatement): void {
  const tk = stmt.tokens;
  const q = readQualifiedName(tk, 2);
  if (!q) return;
  const key = q.name.toLowerCase();
  const labels = state.enums.get(key);
  if (!labels) return;
  let i = q.next;
  if (isWord(tk[i], "add") && isWord(tk[i + 1], "value")) {
    i += 2;
    if (isWord(tk[i], "if") && isWord(tk[i + 1], "not") && isWord(tk[i + 2], "exists")) i += 3;
    const label = tk[i];
    if (label?.kind !== "string" || labels.includes(label.value)) return;
    const anchor = tk[i + 2];
    const at = anchor?.kind === "string" ? labels.indexOf(anchor.value) : -1;
    if (isWord(tk[i + 1], "before") && at >= 0) labels.splice(at, 0, label.value);
    else if (isWord(tk[i + 1], "after") && at >= 0) labels.splice(at + 1, 0, label.value);
    else labels.push(label.value);
  } else if (isWord(tk[i], "rename") && isWord(tk[i + 1], "value")) {
    const from = tk[i + 2];
    const to = tk[i + 4];
    if (from?.kind !== "string" || to?.kind !== "string") return;
    const at = labels.indexOf(from.value);
    if (at >= 0) labels[at] = to.value;
  } else if (isWord(tk[i], "rename") && isWord(tk[i + 1], "to")) {
    const next = identOf(tk[i + 2])?.toLowerCase();
    if (!next) return;
    state.enums.delete(key);
    state.enums.set(next, labels);
    retypeColumns(state, key, next);
  }
}

function dropType(state: SqlSchemaState, stmt: SqlStatement): void {
  const tk = stmt.tokens;
  let i = 2;
  if (isWord(tk[i], "if") && isWord(tk[i + 1], "exists")) i += 2;
  for (const part of splitTopLevelTokens(tk.slice(i))) {
    const q = readQualifiedName(part, 0);
    if (q) state.enums.delete(q.name.toLowerCase());
  }
}

/** Drops PL/pgSQL control words in front of a statement: BEGIN, IF ... THEN, EXCEPTION WHEN ... THEN. */
function stripPlpgsqlPrefix(tokens: Token[]): Token[] {
  let i = 0;
  for (let guard = 0; guard < 32 && i < tokens.length; guard += 1) {
    const t = tokens[i];
    if (isWord(t, "begin") || isWord(t, "else") || isWord(t, "loop")) {
      i += 1;
    } else if (["if", "elsif", "exception", "when"].some((w) => isWord(t, w))) {
      const then = findWord(tokens, i + 1, "then");
      if (then < 0) return [];
      i = then + 1;
    } else break;
  }
  return tokens.slice(i);
}

/**
 * DO blocks: older drizzle-kit wraps CREATE TYPE and foreign keys in
 * `DO $$ BEGIN ... EXCEPTION WHEN duplicate_object THEN null; END $$`. Only schema statements are
 * read there; RLS switches and policies inside DO blocks are left alone.
 */
function doBlock(state: SqlSchemaState, stmt: SqlStatement, file: string): void {
  const body = stmt.tokens.find((t) => t.kind === "string");
  if (!body) return;
  for (const inner of splitSqlStatements(body.value)) {
    const tokens = stripPlpgsqlPrefix(inner.tokens);
    if (tokens.length === 0) continue;
    const s: SqlStatement = { ...inner, tokens, line: stmt.line };
    if (isWord(tokens[0], "create") && isWord(tokens[1], "type")) createType(state, s);
    else if (isWord(tokens[0], "alter") && isWord(tokens[1], "type")) alterType(state, s);
    else if (isWord(tokens[0], "alter") && isWord(tokens[1], "table")) {
      alterTable(state, s, file, true);
    }
  }
}

/** Applies one statement (anything but CREATE POLICY, which rls.ts reads). Unknown statements are ignored. */
export function applySchemaStatement(
  state: SqlSchemaState,
  stmt: SqlStatement,
  file: string,
): void {
  const tk = stmt.tokens;
  const w0 = tk[0]?.kind === "word" ? tk[0].value : "";
  const w1 = tk[1]?.kind === "word" ? tk[1].value : "";
  if (w0 === "create") {
    const kind = w1 === "or" && isWord(tk[2], "replace") ? (tk[3]?.value ?? "") : w1;
    if (kind === "table" || kind === "unlogged") createTable(state, stmt, file);
    else if (kind === "type") createType(state, stmt);
    else if (kind === "function") applyCreateFunction(state.functions, stmt, file);
    else if (kind === "unique") createUniqueIndex(state, stmt);
  } else if (w0 === "alter") {
    if (w1 === "table") alterTable(state, stmt, file, false);
    else if (w1 === "type") alterType(state, stmt);
    else if (w1 === "function" || w1 === "routine") applyAlterFunction(state.functions, stmt);
    else if (w1 === "default") applyDefaultPrivileges(state.functions, stmt);
  } else if (w0 === "drop") {
    if (w1 === "table") dropTable(state, stmt);
    else if (w1 === "type") dropType(state, stmt);
    else if (w1 === "function" || w1 === "routine") applyDropFunction(state.functions, stmt);
  } else if (w0 === "grant" || w0 === "revoke") {
    applyGrantRevoke(state.functions, stmt);
  } else if (w0 === "do") {
    doBlock(state, stmt, file);
  } else if (w0 === "insert" || w0 === "update" || w0 === "delete") {
    applyStorageStatement(state.buckets, stmt, file);
  }
}

export function finishSchema(state: SqlSchemaState): SqlSchemaExtras {
  return {
    // fromEntries defines own properties, so a hostile type name like "__proto__" stays a plain key.
    enums: Object.fromEntries([...state.enums].map(([k, v]) => [k, [...v]])),
    sqlFunctions: finishFunctions(state.functions),
    storageBuckets: finishBuckets(state.buckets),
  };
}
