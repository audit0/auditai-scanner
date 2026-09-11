// Bundles the scanner CLI into a single ESM file for the `auditai-scan` npm package.
// Workspace packages are inlined from source; `typescript` stays a regular dependency.
import { chmodSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const outfile = resolve(root, "npm/dist/auditai-scan.mjs");
mkdirSync(dirname(outfile), { recursive: true });

const alias = Object.fromEntries(
  ["core", "parser", "graph", "rules"].map((p) => [
    `@auditai/${p}`,
    resolve(root, `packages/${p}/src/index.ts`),
  ]),
);

await build({
  entryPoints: [resolve(root, "packages/scanner/src/bin.ts")],
  outfile,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  external: ["typescript"],
  alias,
  legalComments: "none",
  logLevel: "info",
});
chmodSync(outfile, 0o755);
