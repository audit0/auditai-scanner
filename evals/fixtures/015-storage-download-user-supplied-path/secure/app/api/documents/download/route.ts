import { NextResponse } from "next/server";
import { createServiceRoleClient, getUserFromRequest } from "@/lib/supabase";

// GET /api/documents/download?path=<object path>
// The service-role client still skips the storage policies, so the handler enforces ownership itself:
// the object must sit directly in the caller's own folder, "<user id>/<file name>".
export async function GET(req: Request) {
  const user = await getUserFromRequest(req);
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const path = new URL(req.url).searchParams.get("path") ?? "";
  const prefix = `${user.id}/`;
  const fileName = path.slice(prefix.length);
  if (!path.startsWith(prefix) || !/^[A-Za-z0-9._-]+$/.test(fileName) || fileName.includes("..")) {
    // Another user's file, a nested path or a traversal attempt: do not reveal which.
    return NextResponse.json({ error: "Not found" }, { status: 404 });
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
