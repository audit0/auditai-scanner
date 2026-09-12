import { NextResponse } from "next/server";
import { createServiceRoleClient } from "@/lib/supabase";

const RETENTION_DAYS = 30;

// POST /api/cron/purge — scheduled cleanup of finished jobs across every tenant.
// Nothing checks who is calling: the scheduler is trusted by URL alone.
export async function POST() {
  const cutoff = new Date(Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString();
  const admin = createServiceRoleClient();
  const { error, count } = await admin
    .from("jobs")
    .delete({ count: "exact" })
    .eq("status", "done")
    .lt("run_at", cutoff);
  if (error) return NextResponse.json({ error: "Purge failed" }, { status: 500 });
  return NextResponse.json({ purged: count ?? 0 });
}
