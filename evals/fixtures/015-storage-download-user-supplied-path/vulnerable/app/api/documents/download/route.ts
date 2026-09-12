import { NextResponse } from "next/server";
import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";

// GET /api/documents/download?path=<object path>
// Authenticated, but not authorized: the path comes straight from the query string and the
// service-role client skips the storage policies, so any signed-in user can download any file.
export async function GET(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const path = new URL(req.url).searchParams.get("path");
  if (!path) {
    return NextResponse.json({ error: "Missing path" }, { status: 400 });
  }

  const supabase = createServiceRoleClient();
  const { data, error } = await supabase.storage.from("documents").download(path);
  if (error || !data) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
  return new NextResponse(data, {
    headers: { "content-type": data.type || "application/octet-stream" },
  });
}
