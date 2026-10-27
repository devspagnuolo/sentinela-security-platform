import { NextResponse } from "next/server";
import { withAuth } from "@/lib/auth/http";
export const runtime = "nodejs";

/** Situação de uma execução (a interface consulta até ela terminar). */
export const GET = withAuth("asset:read", async ({ repo }, _request, { params }: { params: Promise<{ id: string }> }) => {
  const assessment = await repo.getAssessment((await params).id);
  return assessment ? NextResponse.json(assessment) : NextResponse.json({ error: "Avaliação não encontrada." }, { status: 404 });
}, { apiToken: true });
