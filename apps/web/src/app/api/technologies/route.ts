import { NextResponse } from "next/server";
import { withAuth } from "@/lib/auth/http";
export const runtime = "nodejs";

/** GET /api/technologies?assetId=&includeStale=1: inventário passivo de tecnologias dos ativos. */
export const GET = withAuth("asset:read", async ({ repo }, request) => {
  const params = new URL(request.url).searchParams;
  return NextResponse.json(await repo.listTechnologies({ assetId: params.get("assetId") ?? undefined, includeStale: params.get("includeStale") === "1" }));
}, { apiToken: true });
