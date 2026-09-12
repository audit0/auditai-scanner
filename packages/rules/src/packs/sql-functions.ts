/**
 * Read-only views over the SQL the parser already modelled (`ProjectModel.sqlFunctions`,
 * `ProjectModel.storageBuckets`). Rules never read files: a model without these fields knows no
 * functions and no buckets, which means no SECURITY DEFINER finding and no helper-based policy scoping.
 */
import type { ProjectModel, SqlFunctionInfo, StorageBucket } from "@auditai/parser";

/** Functions defined by the migrations, as the parser read them. */
export function sqlFunctionsOf(model: ProjectModel): readonly SqlFunctionInfo[] {
  return model.sqlFunctions ?? [];
}

/** Storage buckets created by the migrations, as the parser read them. */
export function storageBucketsOf(model: ProjectModel): readonly StorageBucket[] {
  return model.storageBuckets ?? [];
}

/** Names (spelled like SqlFunctionInfo.name) of migration functions that read the caller's identity. */
export function callerCheckingFunctions(model: ProjectModel): ReadonlySet<string> {
  return new Set(
    sqlFunctionsOf(model)
      .filter((f) => f.checksCaller)
      .map((f) => f.name),
  );
}

const CALL = /(?:"?([A-Za-z_][A-Za-z0-9_$]*)"?\s*\.\s*)?"?([A-Za-z_][A-Za-z0-9_$]*)"?\s*\(/g;

/** `public.f` -> `f`, `"Private"."f"` -> `private.f`: the spelling SqlFunctionInfo uses. */
function qualified(schema: string | undefined, name: string | undefined): string {
  const s = (schema ?? "public").toLowerCase();
  const n = (name ?? "").toLowerCase();
  return s === "public" ? n : `${s}.${n}`;
}

/**
 * Does an RLS expression call one of these functions? `public.is_member(org_id)`,
 * `org_id in (select fn_user_org_ids())`, `"private"."has_access"(id)`. String literals are ignored.
 */
export function callsFunctionIn(expr: string, names: ReadonlySet<string>): boolean {
  if (names.size === 0) return false;
  for (const c of expr.replace(/'(?:[^']|'')*'/g, "''").matchAll(CALL)) {
    if (names.has(qualified(c[1], c[2]))) return true;
  }
  return false;
}
