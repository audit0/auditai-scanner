import type { StorageBucket } from "./model.js";
import { identList, identOf, qualifiedKey, readQualifiedName } from "./sql-columns.js";
import {
  findWord,
  groupEnd,
  groupInner,
  isPunct,
  isWord,
  type SqlStatement,
  splitTopLevelTokens,
  type Token,
} from "./sql-lexer.js";

/**
 * Supabase Storage buckets created by migrations: `insert into storage.buckets (id, name, public)
 * values (...)`, later `update storage.buckets set public = ... where id = '...'` and deletes.
 * Buckets are private unless `public` is a literal true, as in Supabase.
 */

export interface BucketRegistry {
  buckets: Map<string, StorageBucket>;
}

export function newBucketRegistry(): BucketRegistry {
  return { buckets: new Map() };
}

const TRUE_LITERALS = new Set(["true", "t", "yes", "y", "on", "1"]);

function literal(tokens: readonly Token[] | undefined): string | null {
  const t = tokens?.[0];
  if (!t) return null;
  if (t.kind === "string" || t.kind === "number" || t.kind === "word") return t.value;
  return null;
}

function isTrue(tokens: readonly Token[] | undefined): boolean {
  const v = literal(tokens);
  return v !== null && TRUE_LITERALS.has(v.toLowerCase());
}

/** True when the tokens starting at `from` name `storage.buckets`; returns the index after the name. */
function bucketsTableAt(tokens: readonly Token[], from: number): number {
  const q = readQualifiedName(tokens, from);
  return q && qualifiedKey(q) === "storage.buckets" ? q.next : -1;
}

/** Bucket ids selected by `where id = 'x'`, `where name = 'x'` or `where id in ('a', 'b')`; null without a filter. */
function whereIds(tokens: readonly Token[], from: number): string[] | null {
  const w = findWord(tokens, from, "where");
  if (w < 0) return null;
  const ids: string[] = [];
  for (let i = w + 1; i < tokens.length; i += 1) {
    const col = identOf(tokens[i])?.toLowerCase();
    if (col !== "id" && col !== "name") continue;
    const op = tokens[i + 1];
    if (op?.kind === "op" && op.raw === "=" && tokens[i + 2]?.kind === "string") {
      ids.push(tokens[i + 2]?.value ?? "");
    } else if (isWord(op, "in") && isPunct(tokens[i + 2], "(")) {
      for (const part of splitTopLevelTokens(groupInner(tokens, i + 2))) {
        const v = literal(part);
        if (v !== null) ids.push(v);
      }
    }
  }
  return ids;
}

function applyInsert(reg: BucketRegistry, stmt: SqlStatement, file: string): void {
  const tk = stmt.tokens;
  const at = isWord(tk[1], "into") ? bucketsTableAt(tk, 2) : -1;
  if (at < 0 || !isPunct(tk[at], "(")) return;
  const columns = identList(groupInner(tk, at));
  let i = groupEnd(tk, at) + 1;
  if (!isWord(tk[i], "values")) return;
  i += 1;
  const keepExisting = findWord(tk, i, "nothing") >= 0;
  const idIdx = columns.indexOf("id");
  const nameIdx = columns.indexOf("name");
  const publicIdx = columns.indexOf("public");
  while (isPunct(tk[i], "(")) {
    const values = splitTopLevelTokens(groupInner(tk, i));
    const id = literal(values[idIdx]) ?? literal(values[nameIdx]);
    if (id !== null && !(keepExisting && reg.buckets.has(id))) {
      reg.buckets.set(id, {
        id,
        public: publicIdx >= 0 && isTrue(values[publicIdx]),
        location: { file, line: stmt.line },
      });
    }
    i = groupEnd(tk, i) + 1;
    if (!isPunct(tk[i], ",")) break;
    i += 1;
  }
}

function applyUpdate(reg: BucketRegistry, stmt: SqlStatement): void {
  const tk = stmt.tokens;
  let i = 1;
  if (isWord(tk[i], "only")) i += 1;
  const at = bucketsTableAt(tk, i);
  const set = at < 0 ? -1 : findWord(tk, at, "set");
  if (set < 0) return;
  const where = findWord(tk, set, "where");
  const assignments = tk.slice(set + 1, where < 0 ? tk.length : where);
  let value: boolean | null = null;
  for (const part of splitTopLevelTokens(assignments)) {
    if (identOf(part[0])?.toLowerCase() === "public" && part[1]?.raw === "=") {
      value = isTrue(part.slice(2));
    }
  }
  if (value === null) return;
  const ids = whereIds(tk, set);
  for (const b of reg.buckets.values()) {
    if (ids === null || ids.includes(b.id)) b.public = value;
  }
}

function applyDelete(reg: BucketRegistry, stmt: SqlStatement): void {
  const tk = stmt.tokens;
  const at = isWord(tk[1], "from") ? bucketsTableAt(tk, 2) : -1;
  if (at < 0) return;
  const ids = whereIds(tk, at);
  for (const id of [...reg.buckets.keys()]) {
    if (ids === null || ids.includes(id)) reg.buckets.delete(id);
  }
}

/** Applies INSERT/UPDATE/DELETE on storage.buckets; other statements are ignored. */
export function applyStorageStatement(reg: BucketRegistry, stmt: SqlStatement, file: string): void {
  const first = stmt.tokens[0];
  if (isWord(first, "insert")) applyInsert(reg, stmt, file);
  else if (isWord(first, "update")) applyUpdate(reg, stmt);
  else if (isWord(first, "delete")) applyDelete(reg, stmt);
}

export function finishBuckets(reg: BucketRegistry): StorageBucket[] {
  return [...reg.buckets.values()].map((b) => ({ ...b, location: { ...b.location } }));
}
