import { NextResponse } from "next/server";
import { RepositoryError } from "@/db/repository";
import { withAuth } from "@/lib/auth/http";
import { SCANNER_METHOD_ID } from "@/lib/scanner";
import { wakeWorker } from "@/lib/worker";
export const runtime = "nodejs";

/** Enfileira a avaliação (202). O worker roda o scanner em segundo plano e confere o escopo de novo na hora. */
export const POST = withAuth("assessment:run", async ({ repo }, _request, { params }: { params: Promise<{ id: string }> }) => {
  const { id } = await params;
  const asset = await repo.getAsset(id);
  if (!asset) return NextResponse.json({ error: "Ativo não encontrado." }, { status: 404 });
  // Recusa já na fila quando o escopo não libera; o worker repete a checagem (revogação ou vencimento no meio do caminho).
  if (!asset.scopeOk) {
    await repo.audit("assessment.blocked", "asset", asset.id, { reason: asset.scopeMessage, authorizationId: asset.authorizationId });
    return NextResponse.json({ error: asset.scopeMessage ?? "Ativo fora do escopo autorizado." }, { status: 403 });
  }
  try {
    const { assessment, queued } = await repo.queueAssessment(asset.id, { method: SCANNER_METHOD_ID });
    if (queued) wakeWorker();
    return NextResponse.json({ assessment, queued }, { status: 202 });
  } catch (error) {
    if (error instanceof RepositoryError) return NextResponse.json({ error: error.message }, { status: error.status });
    throw error;
  }
});
