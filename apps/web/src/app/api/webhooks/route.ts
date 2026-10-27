import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { webhookRepository } from "@/db/webhooks";
import { withAuth } from "@/lib/auth/http";
import { parseJson, webhookSchema } from "@/lib/validation";
export const runtime = "nodejs";

const MAX_WEBHOOKS = 20;

export const GET = withAuth("integration:manage", async ({ organizationId, user }) =>
  NextResponse.json(await webhookRepository(await getDb(), organizationId, user.id).list(), { headers: { "Cache-Control": "no-store" } }));

/** Cadastra o webhook. O segredo de assinatura só aparece nesta resposta. */
export const POST = withAuth("integration:manage", async ({ organizationId, user, repo }, request) => {
  const parsed = await parseJson(request, webhookSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  const hooks = webhookRepository(await getDb(), organizationId, user.id);
  if ((await hooks.list()).length >= MAX_WEBHOOKS) return NextResponse.json({ error: `Limite de ${MAX_WEBHOOKS} webhooks por organização.` }, { status: 409 });
  const { webhook, secret } = await hooks.create(parsed.data);
  await repo.audit("webhook.created", "webhook", webhook.id, { name: webhook.name, url: webhook.url, events: webhook.events });
  return NextResponse.json({ webhook, secret }, { status: 201, headers: { "Cache-Control": "no-store" } });
});
