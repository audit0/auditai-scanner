import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Unit tests and the eval harness. Fixture security tests under evals/fixtures/*/security-test are
// meant to run against a live app inside a sandbox, never as part of this suite.
export default defineConfig({
  resolve: {
    alias: [
      {
        find: /^@auditai\/([a-z]+)$/,
        replacement: fileURLToPath(new URL("./packages/$1/src/index.ts", import.meta.url)),
      },
    ],
  },
  test: {
    include: ["packages/*/src/**/*.test.ts", "evals/harness/**/*.test.ts"],
    exclude: ["**/node_modules/**", "evals/fixtures/**"],
    passWithNoTests: true,
  },
});
