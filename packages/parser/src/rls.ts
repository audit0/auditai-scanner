import type { PolicyCommand, RlsTable } from "./model.js";

const CONSTRAINT_WORDS = new Set([
  "primary",
  "unique",
  "constraint",
  "foreign",
  "check",
  "exclude",
  "like",
]);

function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i += 1) if (text.charCodeAt(i) === 10) line += 1;
  return line;
}

/** Returns the text inside the balanced parentheses starting at `open` (index of "("), or null. */
function balanced(text: string, open: number): { inner: string; end: number } | null {
  if (text[open] !== "(") return null;
  let depth = 0;
  for (let i = open; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === "(") depth += 1;
    else if (ch === ")") {
      depth -= 1;
      if (depth === 0) return { inner: text.slice(open + 1, i), end: i };
    }
  }
  return null;
}

function splitTopLevel(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of text) {
    if (ch === "(") depth += 1;
    if (ch === ")") depth -= 1;
    if (ch === "," && depth === 0) {
      out.push(cur);
      cur = "";
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out.map((s) => s.trim()).filter((s) => s.length > 0);
}

// Accepts `t`, `"t"`, `public.t`, `"public".t`, `public."t"` and `"public"."t"` (Drizzle and Makerkit emit the quoted forms).
const IDENT = String.raw`(?:"?public"?\.)?"?([A-Za-z_][A-Za-z0-9_]*)"?`;
const CREATE_TABLE = new RegExp(
  String.raw`^create\s+table\s+(?:if\s+not\s+exists\s+)?${IDENT}\s*\(`,
  "i",
);
const ENABLE_RLS = new RegExp(
  String.raw`^alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?${IDENT}\s+(enable|disable)\s+row\s+level\s+security`,
  "i",
);
const CREATE_POLICY = new RegExp(
  String.raw`^create\s+policy\s+("([^"]+)"|\S+)\s+on\s+${IDENT}`,
  "i",
);

/**
 * Extracts table columns, RLS state and policy details from migration SQL.
 * Statement order matters: later statements override earlier ones.
 */
export function parseSqlForRls(rel: string, text: string, into: Map<string, RlsTable>): void {
  // Drop comments and dollar-quoted function bodies so ";" splitting stays sane.
  const stripped = text
    .replace(/--[^\n]*/g, "")
    .replace(/\$[A-Za-z_]*\$[\s\S]*?\$[A-Za-z_]*\$/g, "$$body$$");
  const ensure = (name: string, index: number): RlsTable => {
    const key = name.toLowerCase();
    let t = into.get(key);
    if (!t) {
      t = {
        table: key,
        rlsEnabled: false,
        policies: [],
        policyDetails: [],
        columns: [],
        location: { file: rel, line: lineAt(stripped, index) },
      };
      into.set(key, t);
    }
    return t;
  };

  let offset = 0;
  for (const raw of stripped.split(";")) {
    const start = offset;
    offset += raw.length + 1;
    const stmt = raw.trim();
    if (!stmt) continue;
    const at = start + raw.indexOf(stmt);

    const ct = CREATE_TABLE.exec(stmt);
    if (ct?.[1]) {
      const t = ensure(ct[1], at);
      const open = stmt.indexOf("(", ct[0].length - 1);
      const body = balanced(stmt, open);
      if (body) {
        for (const part of splitTopLevel(body.inner)) {
          const first = part.split(/\s+/)[0]?.replace(/^"|"$/g, "") ?? "";
          if (first && !CONSTRAINT_WORDS.has(first.toLowerCase()))
            t.columns.push(first.toLowerCase());
        }
      }
      continue;
    }

    const rls = ENABLE_RLS.exec(stmt);
    if (rls?.[1] && rls[2]) {
      ensure(rls[1], at).rlsEnabled = rls[2].toLowerCase() === "enable";
      continue;
    }

    const cp = CREATE_POLICY.exec(stmt);
    if (cp?.[1] && cp[3]) {
      const t = ensure(cp[3], at);
      const name = cp[2] ?? cp[1];
      const rest = stmt.slice(cp[0].length);
      const cmdMatch = /\bfor\s+(select|insert|update|delete|all)\b/i.exec(rest);
      const command = (cmdMatch?.[1]?.toLowerCase() as PolicyCommand | undefined) ?? "all";
      const rolesMatch = /\bto\s+([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*)/i.exec(
        rest,
      );
      const roles = rolesMatch?.[1]
        ? rolesMatch[1].split(/\s*,\s*/).map((r) => r.toLowerCase())
        : [];
      let using: string | null = null;
      let check: string | null = null;
      const u = /\busing\s*\(/i.exec(rest);
      if (u) using = balanced(rest, u.index + u[0].length - 1)?.inner.trim() ?? null;
      const c = /\bwith\s+check\s*\(/i.exec(rest);
      if (c) check = balanced(rest, c.index + c[0].length - 1)?.inner.trim() ?? null;
      t.policies.push(name);
      t.policyDetails.push({
        name,
        command,
        roles,
        using,
        check,
        location: { file: rel, line: lineAt(stripped, at) },
      });
    }
  }
}
