import type ts from "typescript";
import { describe, expect, it } from "vitest";
import { parseSource, topLevelFunctions } from "./ast.js";
import {
  envNamesIn,
  exitKind,
  isCredentialColumn,
  isSecretEnvName,
  isSessionProviderImport,
  secretChecksIn,
  webauthnChecksIn,
} from "./auth-evidence.js";
import { analyzeModule } from "./supabase.js";

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

describe("webauthnChecksIn", () => {
  const passkeys = (body: string): number => {
    const sf = parseSource(
      "x.ts",
      `import { verifyAuthenticationResponse } from "@simplewebauthn/server";
export async function handler(assertion: unknown, credential: unknown) {
${body}
}`,
    );
    const fn = topLevelFunctions(sf).find((f) => f.name === "handler")?.fn;
    if (!fn) throw new Error("no handler");
    return webauthnChecksIn(fn, analyzeModule("x.ts", sf).imports, {
      returnEndsRequest: true,
      storedKey: () => true,
    }).length;
  };

  it("counts a verified assertion that decides the request", () => {
    expect(
      passkeys(`  const v = await verifyAuthenticationResponse({ response: assertion, credential });
  if (!v.verified) return new Response(null, { status: 401 });
  return Response.json({ ok: true });`),
    ).toBe(1);
    expect(
      passkeys(`  let v;
  try { v = await verifyAuthenticationResponse({ response: assertion, credential }); }
  catch { return new Response(null, { status: 401 }); }
  if (v.verified === false) throw new Error("denied");`),
    ).toBe(1);
  });

  it("counts the denial only where it decides every request that goes on (review cx1)", () => {
    // The twin that counts: the denial is a statement of the body, right after the verification.
    expect(
      passkeys(`  const v = await verifyAuthenticationResponse({ response: assertion, credential });
  if (!v.verified) return new Response(null, { status: 401 });
  await admin.from("invoices").select("*");`),
    ).toBe(1);
    // Checked only when the caller asks for it: a request without "strict" reaches the query.
    expect(
      passkeys(`  const v = await verifyAuthenticationResponse({ response: assertion, credential });
  if ((assertion as { strict?: boolean }).strict) {
    if (!v.verified) return new Response(null, { status: 401 });
  }
  await admin.from("invoices").select("*");`),
    ).toBe(0);
    // Verified only in a branch.
    expect(
      passkeys(`  if (credential) {
    const v = await verifyAuthenticationResponse({ response: assertion, credential });
    if (!v.verified) return new Response(null, { status: 401 });
  }
  await admin.from("invoices").select("*");`),
    ).toBe(0);
    // Denied after the query already ran.
    expect(
      passkeys(`  const v = await verifyAuthenticationResponse({ response: assertion, credential });
  await admin.from("invoices").delete().neq("id", "");
  if (!v.verified) return new Response(null, { status: 401 });`),
    ).toBe(0);
    // A denial whose branch does not always leave.
    expect(
      passkeys(`  const v = await verifyAuthenticationResponse({ response: assertion, credential });
  if (!v.verified) { if (Math.random() > 0.5) return new Response(null, { status: 401 }); }
  await admin.from("invoices").select("*");`),
    ).toBe(0);
    // A catch that swallows the failure and carries on.
    expect(
      passkeys(`  let v;
  try { v = await verifyAuthenticationResponse({ response: assertion, credential }); }
  catch { console.error("verification failed"); }
  if (v?.verified === false) return new Response(null, { status: 401 });
  await admin.from("invoices").select("*");`),
    ).toBe(0);
  });

  it("counts a denial by return in a helper only when the caller checks its result", () => {
    const sf = parseSource(
      "x.ts",
      `import { verifyAuthenticationResponse } from "@simplewebauthn/server";
export async function handler(assertion: unknown, credential: unknown) {
  const v = await verifyAuthenticationResponse({ response: assertion, credential });
  if (!v.verified) return false;
  return true;
}`,
    );
    const fn = topLevelFunctions(sf).find((f) => f.name === "handler")?.fn;
    if (!fn) throw new Error("no handler");
    const imports = analyzeModule("x.ts", sf).imports;
    const storedKey = (): boolean => true;
    expect(webauthnChecksIn(fn, imports, { returnEndsRequest: true, storedKey })).toHaveLength(1);
    expect(webauthnChecksIn(fn, imports, { returnEndsRequest: false, storedKey })).toHaveLength(0);
  });

  it("does not count one whose result nothing checks, or one that is not awaited", () => {
    expect(
      passkeys(`  const v = await verifyAuthenticationResponse({ response: assertion, credential });
  console.log(v.verified);
  return Response.json({ ok: true });`),
    ).toBe(0);
    expect(
      passkeys(`  const v = verifyAuthenticationResponse({ response: assertion, credential });
  if (!v.verified) return new Response(null, { status: 401 });`),
    ).toBe(0);
  });
});

describe("webauthnChecksIn: the second review (cx14b, cx14c, cx14d)", () => {
  const run = (
    body: string,
    opts: {
      returnEndsRequest: boolean;
      storedKey: (key: ts.Expression) => boolean;
    },
    head = "",
  ): number => {
    const sf = parseSource(
      "x.ts",
      `import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import { NextResponse } from "next/server";
${head}
export async function handler(req: Request, body: any, row: any) {
${body}
}`,
    );
    const fn = topLevelFunctions(sf).find((f) => f.name === "handler")?.fn;
    if (!fn) throw new Error("no handler");
    return webauthnChecksIn(fn, analyzeModule("x.ts", sf).imports, opts).length;
  };
  const VERIFY = (key: string): string =>
    `await verifyAuthenticationResponse({ response: body.response, credential: { id: row.id, publicKey: ${key}, counter: 0 } })`;
  const always = { returnEndsRequest: true, storedKey: (): boolean => true };

  it("does not take a NextResponse.redirect() that is not returned for an exit (cx14c)", () => {
    const deny = (then: string): number =>
      run(
        `  const v = ${VERIFY("row.key")};
  if (!v.verified) { ${then} }`,
        always,
        `import { redirect } from "next/navigation";`,
      );
    expect(deny(`NextResponse.redirect(new URL("/login", req.url));`)).toBe(0);
    expect(deny(`Response.redirect(new URL("/login", req.url));`)).toBe(0);
    expect(deny(`return NextResponse.redirect(new URL("/login", req.url));`)).toBe(1);
    // redirect() of next/navigation throws: it ends the request.
    expect(deny(`redirect("/login");`)).toBe(1);
  });

  it("counts a catch that returns only where the return ends the request (cx14b)", () => {
    const body = `  let v;
  try { v = ${VERIFY("row.key")}; } catch (e) { console.error(e); return null; }
  if (!v.verified) throw new Error("rejected");`;
    expect(run(body, { ...always, returnEndsRequest: false })).toBe(0);
    expect(run(body, always)).toBe(1);
  });

  it("refuses a return before the verification where the caller ignores the result (w1)", () => {
    const body = (before: string): string => `${before}
  const v = ${VERIFY("row.key")};
  if (!v.verified) throw new Error("rejected");`;
    const ignored = { ...always, returnEndsRequest: false };
    expect(run(body(`  if (!body.response) return null;`), ignored)).toBe(0);
    expect(
      run(body(`  if (!body.response) { console.warn("no assertion"); return; }`), ignored),
    ).toBe(0);
    const inTry = (before: string): string => `  let v;
  try { ${before} v = ${VERIFY("row.key")}; } catch (e) { throw e; }
  if (!v.verified) throw new Error("rejected");`;
    expect(run(inTry(`if (!body.response) return null;`), ignored)).toBe(0);
    expect(run(inTry(""), ignored)).toBe(1);
    // Twins: no return before it, or a throw; and where the caller checks the result, a return does end the request.
    expect(run(body(""), ignored)).toBe(1);
    expect(run(body(`  if (!body.response) throw new Error("no assertion");`), ignored)).toBe(1);
    expect(run(body(`  if (!body.response) return null;`), always)).toBe(1);
  });

  it("asks where the public key comes from (cx14d)", () => {
    const seen: string[] = [];
    const storedKey = (key: ts.Expression): boolean => {
      seen.push(key.getText());
      return !key.getText().includes("body");
    };
    const body = (key: string): string => `  const v = ${VERIFY(key)};
  if (!v.verified) return new Response(null, { status: 401 });`;
    expect(
      run(body(`Buffer.from(body.publicKey, "base64url")`), { returnEndsRequest: true, storedKey }),
    ).toBe(0);
    expect(run(body("row.public_key"), { returnEndsRequest: true, storedKey })).toBe(1);
    expect(seen).toEqual([`Buffer.from(body.publicKey, "base64url")`, "row.public_key"]);
    // No key to see: nothing is counted.
    expect(
      run(
        `  const v = await verifyAuthenticationResponse({ response: body.response, ...body.options });
  if (!v.verified) return new Response(null, { status: 401 });`,
        always,
      ),
    ).toBe(0);
  });
});

describe("exitKind", () => {
  const kind = (code: string, head = ""): string | null => {
    const sf = parseSource("x.ts", `${head}\nexport function handler() {\n${code}\n}`);
    const fn = topLevelFunctions(sf).find((f) => f.name === "handler")?.fn;
    if (!fn?.body) throw new Error("no handler");
    return exitKind(fn.body);
  };

  it("takes redirect() and notFound() of next/navigation for a throw, and nothing of the same name", () => {
    const NAV = `import { redirect, notFound as missing } from "next/navigation";`;
    expect(kind(`redirect("/login");`, NAV)).toBe("throw");
    expect(kind(`missing();`, NAV)).toBe("throw");
    expect(kind(`nav.forbidden();`, `import * as nav from "next/navigation";`)).toBe("throw");
    expect(kind(`NextResponse.redirect(new URL("/login", "https://x"));`, NAV)).toBeNull();
    expect(kind(`redirect("/login");`, `import { redirect } from "./my-nav";`)).toBeNull();
    expect(kind(`return NextResponse.redirect(new URL("/login", "https://x"));`)).toBe("return");
  });
});
