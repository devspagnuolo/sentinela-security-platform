import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { webhookRepository } from "@/db/webhooks";
import { withAuth } from "@/lib/auth/http";
import { parseJson, webhookUpdateSchema } from "@/lib/validation";
export const runtime = "nodejs";

type Params = { params: Promise<{ id: string }> };
const notFound = () => NextResponse.json({ error: "Webhook não encontrado." }, { status: 404 });

/** Webhook com as entregas mais recentes. */
export const GET = withAuth("integration:manage", async ({ organizationId }, _request, { params }: Params) => {
  const hook = await webhookRepository(await getDb(), organizationId).get((await params).id);
  return hook ? NextResponse.json(hook, { headers: { "Cache-Control": "no-store" } }) : notFound();
});

export const PATCH = withAuth("integration:manage", async ({ organizationId, repo }, request, { params }: Params) => {
  const parsed = await parseJson(request, webhookUpdateSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  const { id } = await params;
  const hook = await webhookRepository(await getDb(), organizationId).update(id, parsed.data);
  if (!hook) return notFound();
  await repo.audit("webhook.updated", "webhook", id, parsed.data);
  return NextResponse.json(hook);
});

export const DELETE = withAuth("integration:manage", async ({ organizationId, repo }, _request, { params }: Params) => {
  const { id } = await params;
  const removed = await webhookRepository(await getDb(), organizationId).remove(id);
  if (!removed) return notFound();
  await repo.audit("webhook.deleted", "webhook", id, { name: removed.name, url: removed.url });
  return NextResponse.json({ ok: true });
});
