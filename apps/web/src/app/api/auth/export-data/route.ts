import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { exportPersonalData } from "@/db/privacy";
import { withAuth } from "@/lib/auth/http";
export const runtime = "nodejs";

/** Os dados pessoais de quem está logado (LGPD, art. 18, II). */
export const GET = withAuth("asset:read", async ({ user, organizationId, repo }) => {
  const data = await exportPersonalData(await getDb(), user.id, organizationId);
  if (!data) return NextResponse.json({ error: "Usuário não encontrado." }, { status: 404 });
  await repo.audit("user.data_exported", "user", user.id);
  return NextResponse.json(data, { headers: { "Cache-Control": "no-store", "Content-Disposition": `attachment; filename=sentinela-meus-dados-${data.generatedAt.slice(0, 10)}.json` } });
}, { allowDuringMfaEnrollment: true });
