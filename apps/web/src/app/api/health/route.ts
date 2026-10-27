import { sql } from "drizzle-orm";
import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { logger } from "@/lib/logger";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Sem autenticação, para o healthcheck do Docker e monitores externos.
 * /api/health → processo no ar; /api/health?ready=1 → também consulta o banco.
 * Não expõe versão, configuração nem detalhes do erro.
 */
export async function GET(request: Request) {
  const headers = { "Cache-Control": "no-store" };
  if (!new URL(request.url).searchParams.has("ready")) return NextResponse.json({ status: "ok" }, { headers });
  try {
    await (await getDb()).execute(sql`select 1`);
    return NextResponse.json({ status: "ok", database: "ok" }, { headers });
  } catch (error) {
    logger.error("health.database_unavailable", { error });
    return NextResponse.json({ status: "degraded", database: "unavailable" }, { status: 503, headers });
  }
}
