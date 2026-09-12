/** Fixture 012: invoking the action as Bob must not delete Alice's invoice. Server actions are invoked via the page in the sandbox harness. */
import { createClient } from "@supabase/supabase-js";
import { describe, expect, it } from "vitest";

const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const SEED = JSON.parse(process.env.FIXTURE_SEED_JSON ?? "{}") as Record<"alice" | "bob", { invoiceId: string }>;
const invokeAsBob = process.env.INVOKE_ACTION_AS_BOB; // provided by the sandbox harness: a command that calls deleteInvoice(id) as Bob

describe("deleteInvoice", () => {
  it("DENY: Bob cannot delete Alice's invoice", async () => {
    expect(invokeAsBob, "harness must provide INVOKE_ACTION_AS_BOB").toBeTruthy();
    const { execSync } = await import("node:child_process");
    execSync(`${invokeAsBob} ${SEED.alice.invoiceId}`, { stdio: "ignore" });
    const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });
    const { data } = await admin.from("invoices").select("id").eq("id", SEED.alice.invoiceId).maybeSingle();
    expect(data?.id).toBe(SEED.alice.invoiceId);
  });
});
