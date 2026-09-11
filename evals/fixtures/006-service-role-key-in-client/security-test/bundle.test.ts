/** Fixture 006: after `next build`, the service-role key must not appear in any client chunk. */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const STATIC_DIR = process.env.NEXT_STATIC_DIR ?? join(process.cwd(), ".next", "static");
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith(".js")) out.push(p);
  }
  return out;
}

describe("client bundle", () => {
  it("does not contain the service-role key", () => {
    expect(SERVICE_KEY.length).toBeGreaterThan(10);
    const leaks = walk(STATIC_DIR).filter((f) => readFileSync(f, "utf8").includes(SERVICE_KEY));
    expect(leaks).toEqual([]);
  });
});
