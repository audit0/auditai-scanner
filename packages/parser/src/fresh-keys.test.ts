import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { classKeepsNone, isAllowListPattern, isStrippingPattern } from "./fresh-keys.js";
import type { StorageAccess } from "./model.js";
import { parseProject } from "./parse-project.js";

function tempProject(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "auditai-fresh-keys-"));
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

/** The storage access of every storage call, in source order, for a POST handler with this body. */
function accesses(handlerBody: string, extra: Record<string, string> = {}): StorageAccess[] {
  const model = parseProject(
    tempProject({
      "lib/supabase.ts": LIB,
      "app/api/files/route.ts": `import { randomUUID, randomBytes } from "node:crypto";
import { v4 as uuidv4 } from "uuid";
import { admin, getUserFromRequest } from "@/lib/supabase";
${extra.header ?? ""}
export async function POST(req: Request) {
  const user = await getUserFromRequest(req);
  const body = await req.json();
  const ext = (body.ext as string).replace(/[^a-z0-9]/g, "");
${handlerBody}
  return new Response(null);
}
`,
      ...Object.fromEntries(Object.entries(extra).filter(([k]) => k !== "header")),
    }),
  );
  return model.routes.flatMap((r) => r.queries.flatMap((q) => (q.storage ? [q.storage] : [])));
}

const minted = (s: StorageAccess | undefined): boolean => s?.pathServerMinted === true;

describe("storage keys minted in the request", () => {
  it("counts a random token in the last segment, and not a caller name after it", () => {
    const [ok, after, slashAfter] = accesses(`
  const id = crypto.randomUUID();
  await admin().storage.from("docs").upload(\`org/\${id}.\${ext}\`, new Blob([]));
  await admin().storage.from("docs").upload(\`\${randomUUID()}-\${body.name}\`, new Blob([]));
  await admin().storage.from("docs").upload(\`\${uuidv4()}/\${body.name.replace(/[^a-z0-9]/g, "")}\`, new Blob([]));`);
    expect(ok).toMatchObject({ pathInputDerived: true, pathScopedToCaller: false });
    expect(minted(ok)).toBe(true);
    // `${body.name}` after the token can be `/../victim.pdf`; a literal `/` after it opens a new
    // segment that the stripped name alone fills (`..` survives the stripping).
    expect(minted(after)).toBe(false);
    expect(minted(slashAfter)).toBe(false);
  });

  it("refuses a caller prefix before the token unless an allow-list check dominates it", () => {
    const [unchecked, checked, branchOnly] = accesses(`
  const folder = body.folder as string;
  const other = body.other as string;
  await admin().storage.from("docs").upload(\`\${folder}/\${uuidv4()}.png\`, new Blob([]));
  if (!/^[0-9a-f-]{36}$/i.test(folder)) return new Response(null, { status: 400 });
  await admin().storage.from("docs").upload(\`\${folder}/\${uuidv4()}.png\`, new Blob([]));
  if (body.strict) {
    if (!/^[0-9a-f-]{36}$/i.test(other)) return new Response(null, { status: 400 });
  }
  await admin().storage.from("docs").upload(\`\${other}/\${uuidv4()}.png\`, new Blob([]));`);
    // `victim.pdf?` before the token ends the URL path at the victim's object.
    expect(minted(unchecked)).toBe(false);
    expect(minted(checked)).toBe(true);
    // The check sits in a branch of its own: the path that skips it reaches the upload unchecked.
    expect(minted(branchOnly)).toBe(false);
  });

  it("does not take a pattern that lets `?` or `#` through, or one that is not anchored", () => {
    const [dot, unanchored, multiline] = accesses(`
  const a = body.a as string;
  const b = body.b as string;
  const c = body.c as string;
  if (!/^.+$/.test(a)) return new Response(null, { status: 400 });
  if (!/[a-z]+/.test(b)) return new Response(null, { status: 400 });
  if (!/^[a-z]+$/m.test(c)) return new Response(null, { status: 400 });
  await admin().storage.from("docs").upload(\`\${a}/\${uuidv4()}\`, new Blob([]));
  await admin().storage.from("docs").upload(\`\${b}/\${uuidv4()}\`, new Blob([]));
  await admin().storage.from("docs").upload(\`\${c}/\${uuidv4()}\`, new Blob([]));`);
    expect([minted(dot), minted(unanchored), minted(multiline)]).toEqual([false, false, false]);
  });

  it("strips the tail with a global allow-list class, or looks it up in a slash-free table", () => {
    const [stripped, noGlobal, table, slashTable] = accesses(
      `
  const clean = (body.ext as string).replace(/[^a-z0-9]/gi, "").toLowerCase().slice(0, 5) || "bin";
  const once = (body.ext as string).replace(/[^a-z0-9]/i, "");
  await admin().storage.from("docs").upload(\`org/\${uuidv4()}.\${clean}\`, new Blob([]));
  await admin().storage.from("docs").upload(\`org/\${uuidv4()}.\${once}\`, new Blob([]));
  await admin().storage.from("docs").upload(\`org/\${uuidv4()}.\${EXT_BY_MIME[body.mime].ext}\`, new Blob([]));
  await admin().storage.from("docs").upload(\`org/\${uuidv4()}.\${BAD[body.mime]}\`, new Blob([]));`,
      {
        header: `import { EXT_BY_MIME } from "@/lib/types";
const BAD = { "image/png": "png", "x/y": "../../victim" };`,
        "lib/types.ts": `export const EXT_BY_MIME = { "image/png": { ext: "png" }, "image/jpeg": { ext: "jpg" } } as const;\n`,
      },
    );
    expect(minted(stripped)).toBe(true);
    expect(minted(noGlobal)).toBe(false);
    expect(minted(table)).toBe(true);
    expect(minted(slashTable)).toBe(false);
  });

  it("knows the generator by its module, never by its name", () => {
    const [hex, b64, fake, moduleToken, dateOnly] = accesses(
      `
  await admin().storage.from("docs").upload(\`org/\${randomBytes(16).toString("hex")}.\${ext}\`, new Blob([]));
  await admin().storage.from("docs").upload(\`org/\${randomBytes(16).toString("base64")}.\${ext}\`, new Blob([]));
  await admin().storage.from("docs").upload(\`org/\${v4()}.\${ext}\`, new Blob([]));
  await admin().storage.from("docs").upload(\`org/\${RUN}.\${ext}\`, new Blob([]));
  await admin().storage.from("docs").upload(\`org/\${Date.now()}.\${ext}\`, new Blob([]));`,
      {
        header: `import { v4 } from "@/lib/uuid";
const RUN = crypto.randomUUID();`,
        "lib/uuid.ts": `export function v4() { return "fixed"; }\n`,
      },
    );
    expect(minted(hex)).toBe(true);
    // Standard base64 has `/` in its alphabet.
    expect(minted(b64)).toBe(false);
    expect(minted(fake)).toBe(false);
    // Minted once per process, shared by every request.
    expect(minted(moduleToken)).toBe(false);
    expect(minted(dateOnly)).toBe(false);
  });

  it("follows the key through a path helper and into the helper that signs it", () => {
    const [helperKey, datedKey] = accesses(
      `
  const raw = body.raw as string;
  const path = videoPath(user!.id, crypto.randomUUID(), raw);
  await createUploadUrl(path);
  const dated = datedPath(user!.id, raw);
  await createUploadUrl(dated);`,
      {
        header: `import { createUploadUrl, datedPath, videoPath } from "@/lib/paths";`,
        "lib/paths.ts": `import { admin } from "@/lib/supabase";
export function videoPath(loc: string, id: string, ext: string): string {
  const cleanExt = ext.replace(/[^a-z0-9]/gi, "").toLowerCase().slice(0, 5) || "mp4";
  return \`\${loc}/videos/\${id}.\${cleanExt}\`;
}
export function datedPath(loc: string, ext: string): string {
  const cleanExt = ext.replace(/[^a-z0-9]/gi, "") || "mp4";
  return \`\${loc}/videos/\${Date.now()}.\${cleanExt}\`;
}
export async function createUploadUrl(path: string) {
  return admin().storage.from("videos").createSignedUploadUrl(path);
}
`,
      },
    );
    expect(helperKey).toMatchObject({ op: "createSignedUploadUrl", pathInputDerived: true });
    expect(minted(helperKey)).toBe(true);
    expect(datedKey).toMatchObject({ op: "createSignedUploadUrl", pathInputDerived: true });
    expect(minted(datedKey)).toBe(false);
  });

  it("does not trust a name that is reassigned or shadowed", () => {
    const [reassigned, shadowed] = accesses(`
  let key = \`org/\${uuidv4()}.\${ext}\`;
  if (body.k) key = body.k;
  await admin().storage.from("docs").remove([key]);
  const k = \`org/\${uuidv4()}.\${ext}\`;
  await Promise.all((body.keys as string[]).map((k) => admin().storage.from("docs").remove([k])));`);
    expect(reassigned).toMatchObject({ pathInputDerived: true });
    expect(minted(reassigned)).toBe(false);
    expect(shadowed).toMatchObject({ pathInputDerived: true });
    expect(minted(shadowed)).toBe(false);
  });
});

describe("character-set proofs", () => {
  it("reads stripping classes", () => {
    expect(isStrippingPattern("/[^a-z0-9]/gi", "/\\")).toBe(true);
    expect(isStrippingPattern("/[^a-zA-Z0-9._-]+/g", "/\\")).toBe(true);
    expect(isStrippingPattern("/[^a-z0-9/]/g", "/\\")).toBe(false);
    expect(isStrippingPattern("/[^!-~]/g", "/\\")).toBe(false);
    expect(isStrippingPattern("/[^\\!-~]/g", "/\\")).toBe(false);
    expect(isStrippingPattern("/[^a-z\\x2f]/g", "/\\")).toBe(false);
    expect(isStrippingPattern("/[a-z]/g", "/\\")).toBe(false);
  });

  it("reads allow-list patterns", () => {
    const uuid = "/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i";
    expect(isAllowListPattern(uuid, "?#")).toBe(true);
    expect(isAllowListPattern("/^[\\w-]+$/", "?#")).toBe(true);
    expect(isAllowListPattern("/^a|b$/", "?#")).toBe(false);
    expect(isAllowListPattern("/^[^/]+$/", "?#")).toBe(false);
    expect(isAllowListPattern("/^[a-z]+\\?$/", "?#")).toBe(false);
    expect(isAllowListPattern("/^[a-z#]+$/", "?#")).toBe(false);
    expect(isAllowListPattern("/^[a-z]+$/m", "?#")).toBe(false);
  });

  it("keeps ranges to letters and digits", () => {
    expect(classKeepsNone("a-zA-Z0-9_.-", "/\\?#")).toBe(true);
    expect(classKeepsNone("+-9", "/\\")).toBe(false);
    expect(classKeepsNone("\\u002f", "/\\")).toBe(false);
  });
});
