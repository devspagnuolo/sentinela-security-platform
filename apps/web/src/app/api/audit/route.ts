import { NextResponse } from "next/server";
import { requestRepository } from "@/lib/tenant";
export const runtime = "nodejs";
export async function GET(request: Request) {
  const limit = Number(new URL(request.url).searchParams.get("limit") ?? 100);
  return NextResponse.json(await (await requestRepository()).listAudit(Number.isFinite(limit) ? limit : 100), { headers: { "Cache-Control": "no-store" } });
}
