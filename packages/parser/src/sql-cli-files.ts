/** A migration the Supabase CLI applies in order: `supabase/migrations/<version>_<name>.sql`. */
export const CLI_MIGRATION = /(?:^|\/)supabase\/migrations\/[0-9]+_[^/]*\.sql$/;

export function isCliMigrationFile(rel: string): boolean {
  return CLI_MIGRATION.test(rel.split("\\").join("/"));
}
