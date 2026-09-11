export * from "./packs/supabase-authorization.js";
export * from "./rule.js";

import { supabaseAuthorizationPack } from "./packs/supabase-authorization.js";
import type { Rule } from "./rule.js";

/** All rule packs enabled in v0. */
export const defaultRules: readonly Rule[] = [...supabaseAuthorizationPack];
