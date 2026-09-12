import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "@/db/schema";

/**
 * Direct Postgres connection as the database owner. Nothing here goes through PostgREST, so the
 * RLS policies in the migrations never run for these queries.
 */
const client = postgres(process.env.DATABASE_URL!, { prepare: false });
export const db = drizzle(client, { schema });
