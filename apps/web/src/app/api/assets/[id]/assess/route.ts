import { NextResponse } from "next/server";
import { store } from "@/lib/store";
import { assess } from "@/lib/scanner";
import { randomUUID } from "node:crypto";
export const runtime = "nodejs";
export async function POST(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const asset = store.assets.find(item => item.id === id);
  if (!asset) return NextResponse.json({ error: "Ativo não encontrado." }, { status: 404 });
  if (!asset.approved) return NextResponse.json({ error: "O ativo precisa ser aprovado no fluxo de autorização antes da avaliação." }, { status: 403 });
  try {
    const startedAt = new Date().toISOString();
    const findings = await assess(asset);
    store.findings.unshift(...findings);
    const run = { id: randomUUID(), assetId: asset.id, status: "completed" as const, startedAt, findingIds: findings.map(item => item.id) };
    store.assessments.unshift(run);
    return NextResponse.json({ run, findings });
  } catch (error) { return NextResponse.json({ error: error instanceof Error ? error.message : "Falha na avaliação." }, { status: 400 }); }
}
