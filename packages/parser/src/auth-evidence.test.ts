import { describe, expect, it } from "vitest";
import { parseSource, topLevelFunctions } from "./ast.js";
import {
  envNamesIn,
  isCredentialColumn,
  isSecretEnvName,
  isSessionProviderImport,
  secretChecksIn,
} from "./auth-evidence.js";

/** Secret checks found in the function named `name` of a source snippet. */
function checks(code: string, name = "handler"): string[] {
  const sf = parseSource("x.ts", code);
  const fn = topLevelFunctions(sf).find((f) => f.name === name)?.fn;
  if (!fn) throw new Error(`no function ${name}`);
  return secretChecksIn(fn, sf).map((c) => c.text);
}

describe("secret names", () => {
  it("knows server secrets from public config", () => {
    expect(isSecretEnvName("CRON_SECRET")).toBe(true);
    expect(isSecretEnvName("ADMIN_PASSWORD")).toBe(true);
    expect(isSecretEnvName("INTERNAL_API_KEY")).toBe(true);
    expect(isSecretEnvName("SUPABASE_SERVICE_ROLE_KEY")).toBe(true);
    expect(isSecretEnvName("NEXT_PUBLIC_SUPABASE_ANON_KEY")).toBe(false);
    expect(isSecretEnvName("SUPABASE_ANON_KEY")).toBe(false);
    expect(isSecretEnvName("NODE_ENV")).toBe(false);
    expect(isSecretEnvName("SUPABASE_URL")).toBe(false);
  });

  it("reads env names through process.env, env objects and env getters", () => {
    const sf = parseSource(
      "x.ts",
      'const a = [process.env.CRON_SECRET, process.env["API_KEY"], env.WEBHOOK_SECRET, getRuntimeEnv("ADMIN_PASSWORD")];',
    );
    expect(envNamesIn(sf)).toEqual(["CRON_SECRET", "API_KEY", "WEBHOOK_SECRET", "ADMIN_PASSWORD"]);
  });
});

describe("secretChecksIn", () => {
  it("finds a cron secret compared with the Authorization header and an early return", () => {
    expect(
      checks(`export async function handler(req: Request) {
  if (req.headers.get("authorization") !== \`Bearer \${process.env.CRON_SECRET}\`) {
    return new Response("Unauthorized", { status: 401 });
  }
}`),
    ).toHaveLength(1);
  });

  it("follows the secret through local variables into a constant-time compare (wacrm cron)", () => {
    const found = checks(`import { timingSafeEqual } from "node:crypto";
export async function handler(request: Request) {
  const expected = process.env.AUTOMATION_CRON_SECRET;
  if (!expected) return Response.json({ error: "cron not configured" }, { status: 503 });
  const supplied = request.headers.get("x-cron-secret") ?? "";
  const suppliedBuf = Buffer.from(supplied);
  const expectedBuf = Buffer.from(expected);
  if (suppliedBuf.length !== expectedBuf.length || !timingSafeEqual(suppliedBuf, expectedBuf)) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
}`);
    expect(found.some((t) => t.startsWith("timingSafeEqual("))).toBe(true);
  });

  it("counts a predicate helper that returns the comparison (its caller branches on it)", () => {
    expect(
      checks(
        `export function isAuthorized(token: string) { return token === process.env.INTERNAL_API_KEY; }`,
        "isAuthorized",
      ),
    ).toHaveLength(1);
  });

  it("follows a secret produced by a same-module helper (HMAC with the session secret)", () => {
    expect(
      checks(
        `function sessionSecret() { return getRuntimeEnv("ADMIN_SESSION_SECRET"); }
function sign(payload: string) { return createHmac("sha256", sessionSecret()).update(payload).digest("hex"); }
export function verifyToken(token: string, signature: string) {
  const expected = sign(token);
  return timingSafeEqual(signature, expected);
}`,
        "verifyToken",
      ),
    ).toHaveLength(1);
  });

  it("counts signature and token verification with a secret key", () => {
    expect(
      checks(`export async function handler(req: Request) {
  const event = stripe.webhooks.constructEvent(await req.text(), req.headers.get("stripe-signature")!, process.env.STRIPE_WEBHOOK_SECRET!);
}`),
    ).toHaveLength(1);
    expect(
      checks(`export async function handler(req: Request) {
  const claims = jwt.verify(req.headers.get("x-token")!, process.env.JWT_SECRET!);
}`),
    ).toHaveLength(1);
  });

  it("ignores comparisons that decide nothing, config checks and public values", () => {
    expect(
      checks(`export async function handler(req: Request) {
  const ok = req.headers.get("x-key") === process.env.API_KEY;
  console.log(ok);
  if (process.env.NODE_ENV !== "production") return new Response("dev only");
  if (!process.env.CRON_SECRET) return new Response("not configured");
  if (process.env.CRON_SECRET === "") return new Response("empty");
  if (req.headers.get("x-key") === process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY) return new Response("anon");
}`),
    ).toEqual([]);
  });

  it("does not treat a helper merely named like auth as a check", () => {
    expect(
      checks(`export async function requireAdmin(req: Request) { return true; }`, "requireAdmin"),
    ).toEqual([]);
  });
});

describe("session providers and credential columns", () => {
  it("recognises session functions of known auth libraries by import", () => {
    expect(isSessionProviderImport("next-auth", "getServerSession")).toBe(true);
    expect(isSessionProviderImport("next-auth/next", "getServerSession")).toBe(true);
    expect(isSessionProviderImport("@clerk/nextjs/server", "auth")).toBe(true);
    expect(isSessionProviderImport("@/lib/auth", "auth")).toBe(false);
    expect(isSessionProviderImport("next-auth", "signIn")).toBe(false);
  });

  it("knows columns that hold a credential", () => {
    expect(isCredentialColumn("key_hash")).toBe(true);
    expect(isCredentialColumn("api_key")).toBe(true);
    expect(isCredentialColumn("token_hash")).toBe(true);
    expect(isCredentialColumn("id")).toBe(false);
    expect(isCredentialColumn("tenant_id")).toBe(false);
    expect(isCredentialColumn(null)).toBe(false);
  });
});
