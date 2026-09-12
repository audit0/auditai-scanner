import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import type { SupabaseQuery } from "./model.js";
import { parseProject } from "./parse-project.js";

function tempProject(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "auditai-storage-"));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}

const LIB = `import { createClient } from "@supabase/supabase-js";
export function admin() { return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!); }
export async function getUserFromRequest(req: Request) {
  const { data } = await admin().auth.getUser(req.headers.get("authorization") ?? "");
  return data.user;
}
`;

function storageQueries(files: Record<string, string>): SupabaseQuery[] {
  const m = parseProject(tempProject({ "lib/supabase.ts": LIB, ...files }));
  return m.routes.flatMap((r) => r.queries);
}

describe("Supabase Storage calls", () => {
  it("reads a storage download as a storage.objects access, not a table query", () => {
    const [q, ...rest] = storageQueries({
      "app/api/files/route.ts": `import { admin, getUserFromRequest } from "@/lib/supabase";
export async function GET(req: Request) {
  const user = await getUserFromRequest(req);
  const path = new URL(req.url).searchParams.get("path")!;
  const { data } = await admin().storage.from("documents").download(path);
  const url = admin().storage.from("documents").getPublicUrl(path);
  return new Response(data);
}
`,
    });
    expect(rest).toEqual([]);
    expect(q).toMatchObject({
      table: "storage.objects",
      operation: "select",
      client: "service_role",
      filters: [],
      payload: null,
      storage: {
        bucket: "documents",
        op: "download",
        pathText: "path",
        pathInputDerived: true,
        pathScopedToCaller: false,
      },
    });
  });

  it("sees the caller's id in the path, through a variable or a startsWith/split guard", () => {
    const qs = storageQueries({
      "app/api/files/route.ts": `import { admin, getUserFromRequest } from "@/lib/supabase";
const BUCKET = "documents";
export async function POST(req: Request) {
  const user = await getUserFromRequest(req);
  const { name, path, other, moved } = await req.json();
  const bucket = admin().storage.from(BUCKET);
  const objectPath = \`\${user!.id}/\${name}\`;
  await bucket.upload(objectPath, new Blob([]));
  if (!path.startsWith(\`\${user!.id}/\`)) return new Response(null, { status: 404 });
  await bucket.remove([path]);
  if (moved.split("/")[0] !== user!.id) return new Response(null, { status: 404 });
  await admin().storage.from("documents").move(moved, \`\${user!.id}/archive/\${name}\`);
  await admin().storage.from("documents").copy(other, \`\${user!.id}/copy\`);
  await admin().storage.from("documents").list(\`\${user!.id}/\`);
  return new Response(null);
}
`,
    });
    expect(qs.map((q) => [q.storage?.op, q.operation, q.storage?.bucket])).toEqual([
      ["upload", "insert", "documents"],
      ["remove", "delete", "documents"],
      ["move", "update", "documents"],
      ["copy", "insert", "documents"],
      ["list", "select", "documents"],
    ]);
    expect(qs.map((q) => [q.storage?.pathInputDerived, q.storage?.pathScopedToCaller])).toEqual([
      [true, true],
      [true, true],
      [true, true],
      [true, false],
      [false, true],
    ]);
  });

  it("does not take an id from the request for the caller's id", () => {
    const [q] = storageQueries({
      "app/api/users/[userId]/files/route.ts": `import { admin, getUserFromRequest } from "@/lib/supabase";
export async function GET(req: Request, { params }: { params: Promise<{ userId: string }> }) {
  const user = await getUserFromRequest(req);
  const { userId } = await params;
  const file = new URL(req.url).searchParams.get("file");
  const { data } = await admin().storage.from("avatars").createSignedUrl(\`\${userId}/\${file}\`, 60);
  return Response.json({ url: data?.signedUrl, me: user?.id });
}
`,
    });
    expect(q?.storage).toMatchObject({
      op: "createSignedUrl",
      bucket: "avatars",
      pathInputDerived: true,
      pathScopedToCaller: false,
    });
  });

  it("follows the client into a helper and keeps the path taint", () => {
    const [q] = storageQueries({
      "lib/files.ts": `import type { SupabaseClient } from "@supabase/supabase-js";
export async function fetchFile(client: SupabaseClient, key: string) {
  return client.storage.from(process.env.BUCKET!).download(key);
}
`,
      "app/actions.ts": `"use server";
import { admin } from "@/lib/supabase";
import { fetchFile } from "@/lib/files";
export async function getFile(key: string) {
  return fetchFile(admin(), key);
}
`,
    });
    expect(q).toMatchObject({ client: "service_role", location: { file: "lib/files.ts" } });
    expect(q?.storage).toMatchObject({ bucket: null, pathInputDerived: true });
    expect(q?.via?.[0]).toMatch(/^fetchFile /);
  });
});
