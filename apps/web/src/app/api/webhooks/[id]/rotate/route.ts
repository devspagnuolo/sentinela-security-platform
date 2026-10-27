import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { webhookRepository } from "@/db/webhooks";
import { withAuth } from "@/lib/auth/http";
export const runtime = "nodejs";

/** Gera um novo segredo de assinatura; o anterior deixa de valer imediatamente. */
export const POST = withAuth("integration:manage", async ({ organizationId, repo }, _request, { params }: { params: Promise<{ id: string }> }) => {
  const { id } = await params;
  const secret = await webhookRepository(await getDb(), organizationId).rotateSecret(id);
  if (!secret) return NextResponse.json({ error: "Webhook não encontrado." }, { status: 404 });
  await repo.audit("webhook.secret_rotated", "webhook", id);
  return NextResponse.json({ secret }, { headers: { "Cache-Control": "no-store" } });
});
