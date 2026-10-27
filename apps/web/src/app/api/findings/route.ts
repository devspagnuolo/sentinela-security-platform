import { NextResponse } from "next/server";
import { withAuth } from "@/lib/auth/http";
import type { FindingStatus } from "@/lib/types";
export const runtime = "nodejs";

const STATUSES: FindingStatus[] = ["open", "accepted", "fixed", "false_positive"];

/** GET /api/findings?status=open,accepted&assetId=… (sem filtro: todos). */
export const GET = withAuth("asset:read", async ({ repo }, request) => {
  const params = new URL(request.url).searchParams;
  const status = params.get("status")?.split(",").filter((s): s is FindingStatus => STATUSES.includes(s as FindingStatus));
  return NextResponse.json(await repo.listFindings({ status, assetId: params.get("assetId") ?? undefined }), { headers: { "Cache-Control": "no-store" } });
});
