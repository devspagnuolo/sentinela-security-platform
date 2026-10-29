import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { connectorRepository } from "@/db/connectors";
import { withAuth } from "@/lib/auth/http";
export const runtime = "nodejs";

/** GET /api/discovery?includeStale=1: hostnames dos conectores, classificados contra ativos e escopos. */
export const GET = withAuth("asset:read", async ({ organizationId }, request) => {
  const includeStale = new URL(request.url).searchParams.get("includeStale") === "1";
  return NextResponse.json(await connectorRepository(await getDb(), organizationId).listHosts({ includeStale }), { headers: { "Cache-Control": "no-store" } });
}, { apiToken: true });
