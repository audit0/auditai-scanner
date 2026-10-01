/**
 * A SECURITY DEFINER trigger function whose first statement lets the row through for every role but
 * the signed-in ones: `IF current_user NOT IN ('authenticated', 'anon') THEN RETURN NEW; END IF;`.
 * Inside SECURITY DEFINER, `current_user` is the function's owner (postgres when migrations create
 * it), never `authenticated`, so that test is true on every call and nothing after it runs. The
 * guard meant for the Data API guards nothing. The same test in a SECURITY INVOKER function works.
 *
 * Only the leading statement of the body counts: a guard nested in a branch is not judged. A
 * condition counts when it is true for the owner by itself or as one side of a top-level OR.
 * `session_user` is left alone. Text matching; never throws.
 */
export function definerGuardSkipsEveryone(body: string): boolean {
  const lead =
    /^\s*(?:declare\b[\s\S]*?)?\bbegin\b\s*if\b([\s\S]*?)\bthen\s+return\s+(?:new|old|null)\s*;/i.exec(
      body,
    );
  const cond = lead?.[1];
  if (cond === undefined || cond.length > 400) return false;
  if (/\band\b/i.test(cond)) return false;
  return cond.split(/\bor\b/i).some(trueForOwner);
}

/** Roles that own functions created by migrations on Supabase. */
const OWNERS = new Set(["postgres", "supabase_admin"]);

const ROLE_FN = "(?:current_user|current_role)";
const LIST = String.raw`\(\s*((?:'[^']*'\s*,?\s*)+)\)`;

function names(list: string): string[] {
  return [...list.matchAll(/'([^']*)'/g)].map((m) => (m[1] ?? "").toLowerCase());
}

function trueForOwner(part: string): boolean {
  const p = part.trim().replace(/^\(\s*([\s\S]*)\s*\)$/, "$1");
  const notIn = new RegExp(
    String.raw`^${ROLE_FN}(?:\s*::\s*text)?\s+not\s+in\s*${LIST}$`,
    "i",
  ).exec(p);
  if (notIn) return !names(notIn[1] ?? "").some((n) => OWNERS.has(n));
  const inList = new RegExp(String.raw`^${ROLE_FN}(?:\s*::\s*text)?\s+in\s*${LIST}$`, "i").exec(p);
  if (inList) return names(inList[1] ?? "").some((n) => OWNERS.has(n));
  const cmp = new RegExp(
    String.raw`^${ROLE_FN}(?:\s*::\s*text)?\s*(<>|!=|=)\s*'([^']*)'$`,
    "i",
  ).exec(p);
  if (cmp) {
    const owner = OWNERS.has((cmp[2] ?? "").toLowerCase());
    return cmp[1] === "=" ? owner : !owner;
  }
  return false;
}
