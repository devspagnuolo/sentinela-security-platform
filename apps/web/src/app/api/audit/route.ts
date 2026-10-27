import { NextResponse } from "next/server";
import { withAuth } from "@/lib/auth/http";
export const runtime = "nodejs";
export const GET = withAuth("audit:read", async ({ repo }, request) => {
  const limit = Number(new URL(request.url).searchParams.get("limit") ?? 100);
  return NextResponse.json(await repo.listAudit(Number.isFinite(limit) ? limit : 100), { headers: { "Cache-Control": "no-store" } });
});
