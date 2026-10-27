import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { deliver, webhookRepository } from "@/db/webhooks";
import { withAuth } from "@/lib/auth/http";
export const runtime = "nodejs";

/** Envia agora um evento webhook.test e devolve o resultado da entrega. */
export const POST = withAuth("integration:manage", async ({ organizationId, repo }, _request, { params }: { params: Promise<{ id: string }> }) => {
  const { id } = await params;
  const db = await getDb();
  const pending = await webhookRepository(db, organizationId).queueTest(id);
  if (!pending) return NextResponse.json({ error: "Webhook não encontrado." }, { status: 404 });
  const delivery = await deliver(db, pending);
  await repo.audit("webhook.tested", "webhook", id, { status: delivery.status, responseStatus: delivery.responseStatus });
  return NextResponse.json(delivery);
});
