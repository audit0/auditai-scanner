/**
 * A small PostgreSQL lexer for migration files. It splits statements correctly (a semicolon inside a
 * string, a quoted identifier, a dollar-quoted body or a comment does not end a statement) and hands
 * statement parsers a token stream. Never throws: unterminated constructs simply run to the end.
 */

export type TokenKind = "word" | "ident" | "string" | "number" | "punct" | "op";

export interface Token {
  kind: TokenKind;
  /** Source text of the token. */
  raw: string;
  /** word: lowercased; ident: unquoted, verbatim; string: unescaped contents; others: raw. */
  value: string;
  /** Offsets in the lexed text. */
  start: number;
  end: number;
}

export interface SqlStatement {
  tokens: Token[];
  /** Offset of the first token in the lexed text. */
  start: number;
  /** 1-based line of the first token. */
  line: number;
  /** Source of the statement with comments blanked out (same length, so token offsets line up). */
  text: string;
}

const OP_CHARS = "+-*/<>=~!@#%^&|`?";
const PUNCT = "()[],;.";
const DOLLAR = /\$([A-Za-z_][A-Za-z0-9_]*)?\$/y;
const NUMBER = /(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?/y;
const ESCAPES: Record<string, string> = {
  n: String.fromCharCode(10),
  t: String.fromCharCode(9),
  r: String.fromCharCode(13),
};

function isIdentStart(code: number): boolean {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 95 || code >= 128;
}

function isIdentPart(code: number): boolean {
  return isIdentStart(code) || (code >= 48 && code <= 57) || code === 36;
}

function isDigit(code: number): boolean {
  return code >= 48 && code <= 57;
}

function readQuoted(
  text: string,
  from: number,
  quote: "'" | '"',
  backslashEscapes: boolean,
): { end: number; value: string } {
  let value = "";
  let j = from + 1;
  while (j < text.length) {
    const c = text.charAt(j);
    if (backslashEscapes && c === "\\" && j + 1 < text.length) {
      const e = text.charAt(j + 1);
      value += ESCAPES[e] ?? e;
      j += 2;
      continue;
    }
    if (c === quote) {
      if (text.charAt(j + 1) === quote) {
        value += quote;
        j += 2;
        continue;
      }
      return { end: j + 1, value };
    }
    value += c;
    j += 1;
  }
  return { end: text.length, value };
}

function lineStarts(text: string): number[] {
  const out = [0];
  for (let i = 0; i < text.length; i += 1) if (text.charCodeAt(i) === 10) out.push(i + 1);
  return out;
}

function lineOfOffset(starts: readonly number[], offset: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if ((starts[mid] ?? 0) <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

interface Lexed {
  tokens: Token[];
  /** The input with comments replaced by spaces (line breaks kept). */
  masked: string;
}

function lex(input: string): Lexed {
  const text = typeof input === "string" ? input : "";
  const n = text.length;
  const tokens: Token[] = [];
  const comments: Array<[number, number]> = [];
  const push = (kind: TokenKind, start: number, end: number, value?: string): void => {
    const raw = text.slice(start, end);
    tokens.push({ kind, raw, value: value ?? raw, start, end });
  };
  let i = 0;
  while (i < n) {
    const code = text.charCodeAt(i);
    const c = text.charAt(i);
    const next = text.charAt(i + 1);
    if (code <= 32) {
      i += 1;
    } else if (c === "-" && next === "-") {
      const nl = text.indexOf("\n", i);
      const end = nl === -1 ? n : nl;
      comments.push([i, end]);
      i = end;
    } else if (c === "/" && next === "*") {
      let depth = 1;
      let j = i + 2;
      while (j < n && depth > 0) {
        if (text.startsWith("/*", j)) {
          depth += 1;
          j += 2;
        } else if (text.startsWith("*/", j)) {
          depth -= 1;
          j += 2;
        } else j += 1;
      }
      comments.push([i, j]);
      i = j;
    } else if (c === "'") {
      const q = readQuoted(text, i, "'", false);
      push("string", i, q.end, q.value);
      i = q.end;
    } else if (c === '"') {
      const q = readQuoted(text, i, '"', false);
      push("ident", i, q.end, q.value);
      i = q.end;
    } else if (c === "$") {
      DOLLAR.lastIndex = i;
      const m = DOLLAR.exec(text);
      if (m) {
        const tag = m[0];
        const close = text.indexOf(tag, i + tag.length);
        const end = close === -1 ? n : close + tag.length;
        push("string", i, end, text.slice(i + tag.length, close === -1 ? n : close));
        i = end;
      } else {
        // Positional parameter ($1) or a stray dollar sign.
        let j = i + 1;
        while (j < n && isDigit(text.charCodeAt(j))) j += 1;
        push("op", i, j);
        i = j;
      }
    } else if (isDigit(code) || (c === "." && isDigit(text.charCodeAt(i + 1)))) {
      NUMBER.lastIndex = i;
      const m = NUMBER.exec(text);
      const end = m ? i + m[0].length : i + 1;
      push("number", i, end);
      i = end;
    } else if (isIdentStart(code)) {
      let j = i + 1;
      while (j < n && isIdentPart(text.charCodeAt(j))) j += 1;
      const lower = text.slice(i, j).toLowerCase();
      if (
        text.charAt(j) === "'" &&
        (lower === "e" || lower === "b" || lower === "x" || lower === "n")
      ) {
        // E'..' (backslash escapes), B'..' / X'..' bit strings, N'..' national strings.
        const q = readQuoted(text, j, "'", lower === "e");
        push("string", i, q.end, q.value);
        i = q.end;
      } else {
        push("word", i, j, lower);
        i = j;
      }
    } else if (c === ":" && next === ":") {
      push("punct", i, i + 2);
      i += 2;
    } else if (PUNCT.includes(c)) {
      push("punct", i, i + 1);
      i += 1;
    } else if (OP_CHARS.includes(c)) {
      let j = i + 1;
      while (
        j < n &&
        OP_CHARS.includes(text.charAt(j)) &&
        !text.startsWith("--", j) &&
        !text.startsWith("/*", j)
      ) {
        j += 1;
      }
      push("op", i, j);
      i = j;
    } else {
      push("op", i, i + 1);
      i += 1;
    }
  }
  let masked = "";
  let from = 0;
  for (const [s, e] of comments) {
    masked += text.slice(from, s) + text.slice(s, e).replace(/[^\n]/g, " ");
    from = e;
  }
  masked += text.slice(from);
  return { tokens, masked };
}

/** The input with `--` and block comments blanked out; strings and identifiers stay intact. */
export function maskSqlComments(text: string): string {
  return lex(text).masked;
}

/** Splits SQL into statements on semicolons outside strings, identifiers and comments. */
export function splitSqlStatements(text: string): SqlStatement[] {
  const { tokens, masked } = lex(text);
  const starts = lineStarts(masked);
  const out: SqlStatement[] = [];
  let cur: Token[] = [];
  const flush = (): void => {
    const first = cur[0];
    const last = cur[cur.length - 1];
    if (first && last) {
      out.push({
        tokens: cur,
        start: first.start,
        line: lineOfOffset(starts, first.start),
        text: masked.slice(first.start, last.end),
      });
    }
    cur = [];
  };
  for (const t of tokens) {
    if (t.kind === "punct" && t.raw === ";") flush();
    else cur.push(t);
  }
  flush();
  return out;
}

/** True when the token is the bare (unquoted) keyword `word`, given in lowercase. */
export function isWord(t: Token | undefined, word: string): boolean {
  return t !== undefined && t.kind === "word" && t.value === word;
}

export function isPunct(t: Token | undefined, p: string): boolean {
  return t !== undefined && t.kind === "punct" && t.raw === p;
}

/** Index of the token closing the group opened at `open` ("(" or "["); the last index when unbalanced. */
export function groupEnd(tokens: readonly Token[], open: number): number {
  let depth = 0;
  for (let i = open; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (isPunct(t, "(") || isPunct(t, "[")) depth += 1;
    else if (isPunct(t, ")") || isPunct(t, "]")) {
      depth -= 1;
      if (depth <= 0) return i;
    }
  }
  return tokens.length - 1;
}

/** Tokens strictly inside the group opened at `open`. */
export function groupInner(tokens: readonly Token[], open: number): Token[] {
  return tokens.slice(open + 1, groupEnd(tokens, open));
}

/** Splits tokens on commas outside parentheses and brackets. Empty parts are dropped. */
export function splitTopLevelTokens(tokens: readonly Token[]): Token[][] {
  const out: Token[][] = [];
  let cur: Token[] = [];
  let depth = 0;
  for (const t of tokens) {
    if (isPunct(t, "(") || isPunct(t, "[")) depth += 1;
    else if (isPunct(t, ")") || isPunct(t, "]")) depth = Math.max(0, depth - 1);
    if (depth === 0 && isPunct(t, ",")) {
      if (cur.length > 0) out.push(cur);
      cur = [];
    } else cur.push(t);
  }
  if (cur.length > 0) out.push(cur);
  return out;
}

/** Index of the first bare keyword `word` at depth 0 from `from`, or -1. */
export function findWord(tokens: readonly Token[], from: number, word: string): number {
  let depth = 0;
  for (let i = from; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (isPunct(t, "(") || isPunct(t, "[")) depth += 1;
    else if (isPunct(t, ")") || isPunct(t, "]")) depth = Math.max(0, depth - 1);
    else if (depth === 0 && isWord(t, word)) return i;
  }
  return -1;
}
