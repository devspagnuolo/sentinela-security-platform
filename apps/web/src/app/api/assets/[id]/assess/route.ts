import { NextResponse } from "next/server";
import { assess, SCANNER_METHOD_ID } from "@/lib/scanner";
import { withAuth } from "@/lib/auth/http";
export const runtime = "nodejs";
export const POST = withAuth("assessment:run", async ({ repo }, _request, { params }: { params: Promise<{ id: string }> }) => {
  const { id } = await params;
  const asset = await repo.getAsset(id);
  if (!asset) return NextResponse.json({ error: "Ativo não encontrado." }, { status: 404 });
  // A autorização é conferida agora, não no cadastro: revogação ou vencimento bloqueiam na hora.
  if (!asset.scopeOk) {
    await repo.audit("assessment.blocked", "asset", asset.id, { reason: asset.scopeMessage, authorizationId: asset.authorizationId });
    return NextResponse.json({ error: asset.scopeMessage ?? "Ativo fora do escopo autorizado." }, { status: 403 });
  }
  const startedAt = new Date();
  let observed;
  try { observed = await assess(asset); } catch (error) {
    const message = error instanceof Error ? error.message : "Falha na avaliação.";
    await repo.audit("assessment.failed", "asset", asset.id, { error: message });
    return NextResponse.json({ error: message }, { status: 400 });
  }
  const { run, findings } = await repo.recordAssessment(asset.id, SCANNER_METHOD_ID, startedAt, observed);
  return NextResponse.json({ run, findings });
});
