import { randomUUID } from "node:crypto";
import { and, arrayContains, asc, desc, eq, inArray, isNull, lt, lte, or, sql } from "drizzle-orm";
import { z } from "zod";
import { decrypt, encrypt } from "@/lib/crypto";
import { logger } from "@/lib/logger";
import { generateWebhookSecret, httpsTransport, signPayload, SIGNATURE_HEADER, TEST_EVENT, type WebhookEvent, type WebhookTransport } from "@/lib/webhooks";
import type { Database } from "./client";
import { notify } from "./notifications";
import { auditLog, webhookDeliveries, webhooks } from "./schema";

export type Webhook = {
  id: string; name: string; url: string; events: string[]; enabled: boolean; consecutiveFailures: number; disabledReason: string | null;
  createdAt: string; updatedAt: string; lastDelivery: { status: DeliveryStatus; responseStatus: number | null; at: string } | null;
};
type DeliveryStatus = "pending" | "delivered" | "failed";
export type WebhookDelivery = {
  id: string; eventId: string; event: string; status: DeliveryStatus; attempts: number; responseStatus: number | null; lastError: string | null;
  createdAt: string; deliveredAt: string | null; nextAttemptAt: string;
};
export type WebhookInput = { name: string; url: string; events: WebhookEvent[] };

type WebhookRow = typeof webhooks.$inferSelect;
type DeliveryRow = typeof webhookDeliveries.$inferSelect;

/** Espera antes de cada nova tentativa (minutos): 1, 5, 30, 2 h, 12 h. Depois da sexta tentativa, a entrega falha. */
export const RETRY_MINUTES = [1, 5, 30, 120, 720];
export const MAX_DELIVERY_ATTEMPTS = RETRY_MINUTES.length + 1;
/** Entregas seguidas que esgotaram as tentativas até o webhook ser desligado. */
export const DISABLE_AFTER_FAILURES = 5;
export const DELIVERY_RETENTION_DAYS = 30;
const STALE_LOCK_MS = 2 * 60_000;

const isUuid = (value: string) => z.uuid().safeParse(value).success;
const iso = (d: Date | null) => d?.toISOString() ?? null;

const toDelivery = (r: DeliveryRow): WebhookDelivery => ({
  id: r.id, eventId: r.eventId, event: r.event, status: r.status, attempts: r.attempts, responseStatus: r.responseStatus, lastError: r.lastError,
  createdAt: r.createdAt.toISOString(), deliveredAt: iso(r.deliveredAt), nextAttemptAt: r.nextAttemptAt.toISOString()
});

const envelope = (eventId: string, event: string, organizationId: string, data: Record<string, unknown>, now: Date) =>
  ({ id: eventId, type: event, createdAt: now.toISOString(), organizationId, data });

/**
 * Registra o evento para cada webhook ativo da organização que o assina. O envio
 * acontece no worker; aqui só entra na fila, então quem emite nunca espera a rede.
 */
export async function emitEvent(db: Database, organizationId: string, event: WebhookEvent, data: Record<string, unknown>, now = new Date()) {
  const targets = await db.select({ id: webhooks.id }).from(webhooks)
    .where(and(eq(webhooks.organizationId, organizationId), eq(webhooks.enabled, true), arrayContains(webhooks.events, [event])));
  if (!targets.length) return 0;
  const eventId = randomUUID();
  const payload = envelope(eventId, event, organizationId, data, now);
  await db.insert(webhookDeliveries).values(targets.map(t => ({ organizationId, webhookId: t.id, eventId, event, payload, nextAttemptAt: now, createdAt: now })));
  return targets.length;
}

/** Webhooks de uma organização (gestão pela tela de Integrações). */
export function webhookRepository(db: Database, organizationId: string, actorUserId: string | null = null) {
  const own = eq(webhooks.organizationId, organizationId);
  const byId = (id: string) => and(own, eq(webhooks.id, id));

  async function lastDeliveries(ids: string[]) {
    if (!ids.length) return new Map<string, DeliveryRow>();
    const rows = await db.selectDistinctOn([webhookDeliveries.webhookId]).from(webhookDeliveries)
      .where(and(eq(webhookDeliveries.organizationId, organizationId), inArray(webhookDeliveries.webhookId, ids)))
      .orderBy(webhookDeliveries.webhookId, desc(webhookDeliveries.createdAt));
    return new Map(rows.map(r => [r.webhookId, r]));
  }
  const toWebhook = (r: WebhookRow, last?: DeliveryRow): Webhook => ({
    id: r.id, name: r.name, url: r.url, events: r.events, enabled: r.enabled, consecutiveFailures: r.consecutiveFailures, disabledReason: r.disabledReason,
    createdAt: r.createdAt.toISOString(), updatedAt: r.updatedAt.toISOString(),
    lastDelivery: last ? { status: last.status, responseStatus: last.responseStatus, at: (last.deliveredAt ?? last.createdAt).toISOString() } : null
  });

  return {
    async list(): Promise<Webhook[]> {
      const rows = await db.select().from(webhooks).where(own).orderBy(asc(webhooks.createdAt));
      const last = await lastDeliveries(rows.map(r => r.id));
      return rows.map(r => toWebhook(r, last.get(r.id)));
    },

    async get(id: string): Promise<(Webhook & { deliveries: WebhookDelivery[] }) | undefined> {
      if (!isUuid(id)) return undefined;
      const [row] = await db.select().from(webhooks).where(byId(id));
      if (!row) return undefined;
      const deliveries = await db.select().from(webhookDeliveries).where(eq(webhookDeliveries.webhookId, id)).orderBy(desc(webhookDeliveries.createdAt)).limit(30);
      return { ...toWebhook(row, deliveries[0]), deliveries: deliveries.map(toDelivery) };
    },

    /** Cria o webhook e devolve o segredo de assinatura, que não é exibido de novo. */
    async create(input: WebhookInput) {
      const secret = generateWebhookSecret();
      const [row] = await db.insert(webhooks).values({ organizationId, name: input.name, url: input.url, events: input.events, secret: encrypt(secret), createdBy: actorUserId }).returning();
      return { webhook: toWebhook(row), secret };
    },

    /** Altera dados ou liga/desliga. Religar zera o contador de falhas. */
    async update(id: string, changes: Partial<WebhookInput> & { enabled?: boolean }) {
      if (!isUuid(id)) return undefined;
      const [row] = await db.update(webhooks).set({
        ...(changes.name !== undefined && { name: changes.name }), ...(changes.url !== undefined && { url: changes.url }), ...(changes.events !== undefined && { events: changes.events }),
        ...(changes.enabled !== undefined && { enabled: changes.enabled, ...(changes.enabled && { consecutiveFailures: 0, disabledReason: null }) })
      }).where(byId(id)).returning();
      return row && (await this.get(row.id));
    },

    async remove(id: string) {
      if (!isUuid(id)) return undefined;
      const [row] = await db.delete(webhooks).where(byId(id)).returning({ id: webhooks.id, name: webhooks.name, url: webhooks.url });
      return row;
    },

    async rotateSecret(id: string) {
      if (!isUuid(id)) return undefined;
      const secret = generateWebhookSecret();
      const [row] = await db.update(webhooks).set({ secret: encrypt(secret) }).where(byId(id)).returning({ id: webhooks.id });
      return row && secret;
    },

    /** Enfileira um evento de teste só para este webhook (mesmo desligado) e já o marca como em envio. */
    async queueTest(id: string, now = new Date()) {
      if (!isUuid(id)) return undefined;
      const [row] = await db.select({ id: webhooks.id, name: webhooks.name }).from(webhooks).where(byId(id));
      if (!row) return undefined;
      const eventId = randomUUID();
      const [delivery] = await db.insert(webhookDeliveries).values({
        organizationId, webhookId: id, eventId, event: TEST_EVENT, createdAt: now, nextAttemptAt: now, lockedAt: now, attempts: 1,
        payload: envelope(eventId, TEST_EVENT, organizationId, { webhook: { id, name: row.name }, message: "Entrega de teste do Sentinela." }, now)
      }).returning();
      return delivery;
    }
  };
}

// ---- Entrega (worker) --------------------------------------------------------------

/** Pega a próxima entrega vencida (ou travada há muito tempo) e a marca como em envio, atomicamente entre instâncias. */
export async function claimDelivery(db: Database, now = new Date()): Promise<DeliveryRow | undefined> {
  const next = db.select({ id: webhookDeliveries.id }).from(webhookDeliveries)
    .where(and(eq(webhookDeliveries.status, "pending"), lte(webhookDeliveries.nextAttemptAt, now),
      or(isNull(webhookDeliveries.lockedAt), lt(webhookDeliveries.lockedAt, new Date(now.getTime() - STALE_LOCK_MS)))))
    .orderBy(asc(webhookDeliveries.nextAttemptAt)).limit(1).for("update", { skipLocked: true });
  const [row] = await db.update(webhookDeliveries).set({ lockedAt: now, attempts: sql`${webhookDeliveries.attempts} + 1` })
    // "= (subconsulta)": avaliada uma vez (InitPlan), como em claimNext do worker de avaliações.
    .where(and(eq(webhookDeliveries.id, sql`(${next})`), eq(webhookDeliveries.status, "pending"))).returning();
  return row;
}

export type DeliveryDeps = { transport?: WebhookTransport; now?: () => Date };

/** Envia uma entrega já marcada como em envio e grava o resultado (sucesso, nova tentativa ou falha definitiva). */
export async function deliver(db: Database, delivery: DeliveryRow, deps: DeliveryDeps = {}): Promise<WebhookDelivery> {
  const now = () => deps.now?.() ?? new Date();
  const [hook] = await db.select().from(webhooks).where(eq(webhooks.id, delivery.webhookId));
  const isTest = delivery.event === TEST_EVENT;
  if (!hook || (!hook.enabled && !isTest)) {
    const [row] = await db.update(webhookDeliveries).set({ status: "failed", lockedAt: null, lastError: "Webhook desativado antes do envio." }).where(eq(webhookDeliveries.id, delivery.id)).returning();
    return toDelivery(row ?? delivery);
  }
  const body = JSON.stringify(delivery.payload);
  const headers = {
    [SIGNATURE_HEADER]: signPayload(decrypt(hook.secret), body, Math.floor(now().getTime() / 1000)),
    "Sentinela-Event": delivery.event, "Sentinela-Event-Id": delivery.eventId, "Sentinela-Delivery": delivery.id
  };
  let status: number | null = null, error: string | null = null;
  try {
    status = (await (deps.transport ?? httpsTransport)(new URL(hook.url), body, headers)).status;
    if (status < 200 || status >= 300) error = `O destino respondeu HTTP ${status}.`;
  } catch (e) {
    error = (e instanceof Error ? e.message : "Falha ao entregar.").slice(0, 300);
  }
  const at = now();
  if (!error) {
    const [row] = await db.update(webhookDeliveries).set({ status: "delivered", deliveredAt: at, responseStatus: status, lastError: null, lockedAt: null }).where(eq(webhookDeliveries.id, delivery.id)).returning();
    if (!isTest && hook.consecutiveFailures) await db.update(webhooks).set({ consecutiveFailures: 0 }).where(eq(webhooks.id, hook.id));
    return toDelivery(row);
  }
  // O teste não é repetido: o resultado é mostrado na hora para quem clicou.
  if (!isTest && delivery.attempts < MAX_DELIVERY_ATTEMPTS) {
    const retryAt = new Date(at.getTime() + RETRY_MINUTES[delivery.attempts - 1] * 60_000);
    const [row] = await db.update(webhookDeliveries).set({ responseStatus: status, lastError: error, lockedAt: null, nextAttemptAt: retryAt }).where(eq(webhookDeliveries.id, delivery.id)).returning();
    return toDelivery(row);
  }
  const [row] = await db.update(webhookDeliveries).set({ status: "failed", responseStatus: status, lastError: error, lockedAt: null }).where(eq(webhookDeliveries.id, delivery.id)).returning();
  if (!isTest) await recordFailure(db, hook, error, at);
  return toDelivery(row);
}

/** Conta a entrega perdida; no limite, desliga o webhook e avisa a gestão. */
async function recordFailure(db: Database, hook: WebhookRow, error: string, now: Date) {
  const [updated] = await db.update(webhooks).set({ consecutiveFailures: sql`${webhooks.consecutiveFailures} + 1` }).where(eq(webhooks.id, hook.id)).returning();
  if (!updated || updated.consecutiveFailures < DISABLE_AFTER_FAILURES || !updated.enabled) return;
  const reason = `Desligado após ${updated.consecutiveFailures} entregas seguidas sem sucesso. Último erro: ${error}`.slice(0, 500);
  await db.update(webhooks).set({ enabled: false, disabledReason: reason }).where(eq(webhooks.id, hook.id));
  await db.insert(auditLog).values({ organizationId: hook.organizationId, actorUserId: null, action: "webhook.disabled", targetType: "webhook", targetId: hook.id, metadata: { name: hook.name, reason }, createdAt: now });
  await notify(db, hook.organizationId, { audience: "managers" }, { kind: "webhook.disabled", link: "/integracoes", title: `Webhook ${hook.name} foi desligado`, body: reason });
  logger.warn("webhook.disabled", { webhookId: hook.id, organizationId: hook.organizationId });
}

/** Envia o que estiver vencido, com até `concurrency` entregas em paralelo. */
export async function drainDeliveries(db: Database, deps: DeliveryDeps = {}, concurrency = 4) {
  let sent = 0;
  const lane = async () => {
    for (let d = await claimDelivery(db, deps.now?.()); d; d = await claimDelivery(db, deps.now?.())) {
      try { await deliver(db, d, deps); } catch (error) {
        logger.error("webhook.delivery_error", { deliveryId: d.id, error });
        // Adia (ou encerra) para não pegar a mesma entrega de novo no mesmo ciclo.
        const retryAt = new Date((deps.now?.() ?? new Date()).getTime() + 5 * 60_000);
        await db.update(webhookDeliveries).set({ lockedAt: null, lastError: "Erro interno ao enviar.", nextAttemptAt: retryAt, ...(d.attempts >= MAX_DELIVERY_ATTEMPTS && { status: "failed" as const }) })
          .where(eq(webhookDeliveries.id, d.id)).catch(() => undefined);
      }
      sent++;
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, concurrency) }, lane));
  return sent;
}

/** Remove entregas encerradas há mais de DELIVERY_RETENTION_DAYS dias. */
export async function pruneDeliveries(db: Database, now = new Date()) {
  await db.delete(webhookDeliveries).where(and(inArray(webhookDeliveries.status, ["delivered", "failed"]), lt(webhookDeliveries.createdAt, new Date(now.getTime() - DELIVERY_RETENTION_DAYS * 86_400_000))));
}
