import { describe, expect, it } from "vitest";
import { SNAPSHOT_QUERY, WATCH_SNAPSHOT_QUERY } from "./snapshot-query.js";

describe("the night watch query", () => {
  it("is the snapshot query without the one table it would need a grant for", () => {
    expect(SNAPSHOT_QUERY).toContain("from storage.buckets b");
    expect(WATCH_SNAPSHOT_QUERY).not.toContain("storage.buckets");
    expect(WATCH_SNAPSHOT_QUERY).toContain("'buckets', '[]'::jsonb");
    // Nothing else differs: the watch reads the same catalog, the same way.
    const withoutBuckets = (q: string) => q.slice(0, q.indexOf("'buckets'"));
    expect(withoutBuckets(WATCH_SNAPSHOT_QUERY)).toBe(withoutBuckets(SNAPSHOT_QUERY));
  });
});
