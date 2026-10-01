export { roleFromSignupMetadata } from "./packs/role-from-signup-metadata.js";
export { selfAssignableRoleColumn } from "./packs/self-assignable-role.js";
export { selfWritableEntitlementColumn } from "./packs/self-writable-entitlement.js";
export * from "./packs/supabase-authorization.js";
export * from "./packs/supabase-sql-policies.js";
export * from "./packs/supabase-storage-rpc.js";
export * from "./rule.js";
export * from "./tiers.js";

import { supabaseAuthorizationPack } from "./packs/supabase-authorization.js";
import { supabaseSqlPoliciesPack } from "./packs/supabase-sql-policies.js";
import { supabaseStorageRpcPack } from "./packs/supabase-storage-rpc.js";
import type { Rule } from "./rule.js";

/** All rule packs enabled in v0. What the product may claim about each rule is in tiers.ts. */
export const defaultRules: readonly Rule[] = [
  ...supabaseAuthorizationPack,
  ...supabaseStorageRpcPack,
  ...supabaseSqlPoliciesPack,
];
