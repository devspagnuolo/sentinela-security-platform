import { NextResponse } from "next/server";
import { assess, SCANNER_METHOD_ID } from "@/lib/scanner";
import { withAuth } from "@/lib/auth/http";
export const runtime = "nodejs";
export const POST = withAuth("assessment:run", async ({ repo }, _request, { params }: { params: Promise<{ id: string }> }) => {
  const { id } = await params;
  const asset = await repo.getAsset(id);
  if (!asset) return NextResponse.json({ error: "Ativo não encontrado." }, { status: 404 });
  if (!asset.approved) return NextResponse.json({ error: "O ativo precisa ser aprovado no fluxo de autorização antes da avaliação." }, { status: 403 });
  const startedAt = new Date();
  let observed;
  try { observed = await assess(asset); } catch (error) {
    const message = error instanceof Error ? error.message : "Falha na avaliação.";
    await repo.audit("assessment.failed", "asset", asset.id, { error: message });
    return NextResponse.json({ error: message }, { status: 400 });
  }
  const { run, findings } = await repo.recordAssessment(asset.id, SCANNER_METHOD_ID, startedAt, observed.map(({ title, severity, category, description, evidence, recommendation, references }) => ({ title, severity, category, description, evidence, recommendation, references })));
  return NextResponse.json({ run, findings });
});
