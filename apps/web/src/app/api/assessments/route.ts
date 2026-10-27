import { NextResponse } from "next/server";
import { withAuth } from "@/lib/auth/http";
export const runtime = "nodejs";

/** Histórico de execuções (fila, em andamento, concluídas e com falha). */
export const GET = withAuth("asset:read", async ({ repo }, request) => {
  const params = new URL(request.url).searchParams;
  return NextResponse.json(await repo.listAssessments({ assetId: params.get("assetId") ?? undefined, limit: Number(params.get("limit")) || 100 }));
});
