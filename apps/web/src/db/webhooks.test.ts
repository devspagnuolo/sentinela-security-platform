import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { eq } from "drizzle-orm";
import { verifySignature, type WebhookTransport } from "@/lib/webhooks";
import { housekeeping } from "@/lib/worker";
import { createDatabase, type Database } from "./client";
import { notificationRepository } from "./notifications";
import { tenantRepository } from "./repository";
import { organizations, webhookDeliveries, webhooks } from "./schema";
import { memberRepository } from "./users";
import { claimDelivery, deliver, DISABLE_AFTER_FAILURES, drainDeliveries, emitEvent, MAX_DELIVERY_ATTEMPTS, RETRY_MINUTES, webhookRepository } from "./webhooks";

let db: Database;
let n = 0;
const MIN = 60_000;

async function org() {
  const [o] = await db.insert(organizations).values({ slug: `wh-${++n}`, name: `WH ${n}` }).returning();
  const owner = await memberRepository(db, o.id).create({ email: `owner-${n}@wh.example`, name: "Owner", role: "owner", password: "correct-horse-battery-staple" });
  return { orgId: o.id, owner, hooks: webhookRepository(db, o.id, owner.id) };
}
/** Transporte falso que guarda o que recebeu e responde o status pedido (ou lança erro). */
function transport(status: number | Error = 204) {
  const calls: { url: string; body: string; headers: Record<string, string> }[] = [];
  const fn: WebhookTransport = vi.fn(async (url, body, headers) => {
    calls.push({ url: url.toString(), body, headers });
    if (status instanceof Error) throw status;
    return { status };
  });
  return { fn, calls };
}

beforeAll(async () => {
  db = await createDatabase({ NODE_ENV: "test", SENTINELA_SEED_DEMO: "0" });
});
// A fila é global: cada teste começa sem entregas pendentes de outro.
beforeEach(async () => { await db.delete(webhookDeliveries); });

describe("eventos e entregas", () => {
  it("evento vai só para webhooks ativos que o assinam, da própria organização", async () => {
    const a = await org(), b = await org();
    const all = await a.hooks.create({ name: "Todos", url: "https://a.example/all", events: ["assessment.completed", "scope.pending"] });
    await a.hooks.create({ name: "Escopos", url: "https://a.example/scopes", events: ["scope.pending"] });
    const off = await a.hooks.create({ name: "Desligado", url: "https://a.example/off", events: ["assessment.completed"] });
    await a.hooks.update(off.webhook.id, { enabled: false });
    await b.hooks.create({ name: "Outra org", url: "https://b.example", events: ["assessment.completed"] });

    expect(await emitEvent(db, a.orgId, "assessment.completed", { x: 1 })).toBe(1);
    const rows = await db.select().from(webhookDeliveries).where(eq(webhookDeliveries.organizationId, a.orgId));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ webhookId: all.webhook.id, event: "assessment.completed", status: "pending", payload: { type: "assessment.completed", organizationId: a.orgId, data: { x: 1 } } });
    expect(await emitEvent(db, a.orgId, "scope.pending", {})).toBe(2);
    expect(await emitEvent(db, a.orgId, "finding.status_changed", {})).toBe(0);
  });

  it("entrega assinada com o segredo do webhook; o segredo fica cifrado no banco", async () => {
    const a = await org();
    const { webhook, secret } = await a.hooks.create({ name: "SIEM", url: "https://siem.example/in", events: ["scope.pending"] });
    const [stored] = await db.select().from(webhooks).where(eq(webhooks.id, webhook.id));
    expect(stored.secret).not.toContain(secret);
    expect(JSON.stringify(await a.hooks.list())).not.toContain(secret);

    await emitEvent(db, a.orgId, "scope.pending", { scope: { reference: "AUT-1" } });
    const t = transport(200);
    expect(await drainDeliveries(db, { transport: t.fn })).toBe(1);
    const [call] = t.calls;
    expect(call.url).toBe("https://siem.example/in");
    expect(call.headers).toMatchObject({ "Sentinela-Event": "scope.pending" });
    expect(verifySignature(secret, call.body, call.headers["Sentinela-Signature"])).toBe(true);
    expect(JSON.parse(call.body)).toMatchObject({ id: call.headers["Sentinela-Event-Id"], type: "scope.pending", data: { scope: { reference: "AUT-1" } } });
    expect((await a.hooks.get(webhook.id))?.deliveries[0]).toMatchObject({ status: "delivered", responseStatus: 200, attempts: 1 });

    // Depois de trocar o segredo, a assinatura usa o novo.
    const rotated = await a.hooks.rotateSecret(webhook.id);
    await emitEvent(db, a.orgId, "scope.pending", {});
    await drainDeliveries(db, { transport: t.fn });
    expect(verifySignature(rotated!, t.calls[1].body, t.calls[1].headers["Sentinela-Signature"])).toBe(true);
    expect(verifySignature(secret, t.calls[1].body, t.calls[1].headers["Sentinela-Signature"])).toBe(false);
  });

  it("falha tenta de novo com espera crescente e, esgotadas as tentativas, falha", async () => {
    const a = await org();
    const { webhook } = await a.hooks.create({ name: "Instável", url: "https://flaky.example", events: ["scope.pending"] });
    await emitEvent(db, a.orgId, "scope.pending", {});
    let clock = Date.now();
    const now = () => new Date(clock);
    const t = transport(503);
    for (let attempt = 1; attempt < MAX_DELIVERY_ATTEMPTS; attempt++) {
      expect(await drainDeliveries(db, { transport: t.fn, now })).toBe(1);
      const [d] = (await a.hooks.get(webhook.id))!.deliveries;
      expect(d).toMatchObject({ status: "pending", attempts: attempt, responseStatus: 503, lastError: "O destino respondeu HTTP 503." });
      expect(new Date(d.nextAttemptAt).getTime() - clock).toBe(RETRY_MINUTES[attempt - 1] * MIN);
      // Antes do prazo, nada é reenviado.
      expect(await drainDeliveries(db, { transport: t.fn, now })).toBe(0);
      clock += RETRY_MINUTES[attempt - 1] * MIN;
    }
    await drainDeliveries(db, { transport: transport(new Error("Tempo limite excedido ao entregar o webhook.")).fn, now });
    const [d] = (await a.hooks.get(webhook.id))!.deliveries;
    expect(d).toMatchObject({ status: "failed", attempts: MAX_DELIVERY_ATTEMPTS, lastError: "Tempo limite excedido ao entregar o webhook." });
    expect((await a.hooks.get(webhook.id))?.consecutiveFailures).toBe(1);
  });

  it("muitas entregas perdidas seguidas desligam o webhook e avisam a gestão; sucesso zera o contador", async () => {
    const a = await org();
    const { webhook } = await a.hooks.create({ name: "Fora do ar", url: "https://down.example", events: ["scope.pending"] });
    await db.update(webhooks).set({ consecutiveFailures: DISABLE_AFTER_FAILURES - 2 }).where(eq(webhooks.id, webhook.id));
    await emitEvent(db, a.orgId, "scope.pending", {});
    await drainDeliveries(db, { transport: transport(200).fn });
    expect((await a.hooks.get(webhook.id))?.consecutiveFailures).toBe(0);

    await db.update(webhooks).set({ consecutiveFailures: DISABLE_AFTER_FAILURES - 1 }).where(eq(webhooks.id, webhook.id));
    await emitEvent(db, a.orgId, "scope.pending", {});
    await db.update(webhookDeliveries).set({ attempts: MAX_DELIVERY_ATTEMPTS - 1 }).where(eq(webhookDeliveries.status, "pending"));
    await drainDeliveries(db, { transport: transport(500).fn });
    const hook = await a.hooks.get(webhook.id);
    expect(hook).toMatchObject({ enabled: false, consecutiveFailures: DISABLE_AFTER_FAILURES });
    expect(hook?.disabledReason).toContain("HTTP 500");
    expect((await notificationRepository(db, a.orgId, a.owner.id).list())[0]).toMatchObject({ kind: "webhook.disabled", link: "/integracoes" });
    expect((await tenantRepository(db, a.orgId).listAudit(1))[0]).toMatchObject({ action: "webhook.disabled", actorUserId: null });

    // Desligado: eventos novos não entram na fila; religar zera o contador.
    expect(await emitEvent(db, a.orgId, "scope.pending", {})).toBe(0);
    expect(await a.hooks.update(webhook.id, { enabled: true })).toMatchObject({ enabled: true, consecutiveFailures: 0, disabledReason: null });
  });

  it("entrega pendente de webhook desligado depois é descartada; teste é enviado mesmo desligado", async () => {
    const a = await org();
    const { webhook } = await a.hooks.create({ name: "X", url: "https://x.example", events: ["scope.pending"] });
    await emitEvent(db, a.orgId, "scope.pending", {});
    await a.hooks.update(webhook.id, { enabled: false });
    const t = transport(200);
    await drainDeliveries(db, { transport: t.fn });
    expect(t.calls).toHaveLength(0);
    expect((await a.hooks.get(webhook.id))?.deliveries[0]).toMatchObject({ status: "failed", lastError: "Webhook desativado antes do envio." });

    const test = await a.hooks.queueTest(webhook.id);
    expect(await claimDelivery(db)).toBeUndefined();
    expect(await deliver(db, test!, { transport: transport(418).fn })).toMatchObject({ event: "webhook.test", status: "failed", responseStatus: 418 });
    expect((await a.hooks.get(webhook.id))?.consecutiveFailures).toBe(0);
  });

  it("dois workers nunca enviam a mesma entrega", async () => {
    const a = await org();
    await a.hooks.create({ name: "Concorrência", url: "https://c.example", events: ["scope.pending"] });
    for (let i = 0; i < 6; i++) await emitEvent(db, a.orgId, "scope.pending", { i });
    const t = transport(200);
    await Promise.all([drainDeliveries(db, { transport: t.fn }, 3), drainDeliveries(db, { transport: t.fn }, 3)]);
    const ids = t.calls.map(c => c.headers["Sentinela-Delivery"]);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids.length).toBeGreaterThanOrEqual(6);
  });
});

describe("eventos do domínio", () => {
  it("avaliação concluída, escopo e triagem geram eventos com os dados esperados", async () => {
    const a = await org();
    await a.hooks.create({ name: "Tudo", url: "https://all.example", events: ["assessment.completed", "scope.pending", "scope.approved", "finding.status_changed"] });
    const repo = tenantRepository(db, a.orgId, a.owner.id);
    const scope = await repo.createAuthorization({ reference: "AUT-EV", hostnames: ["*.example.com"], excludedHostnames: [], validFrom: null, validUntil: new Date(Date.now() + 30 * 86_400_000), emergencyContact: "plantão 1234" });
    await repo.approveAuthorization(scope.id, { id: a.owner.id, role: "owner" });
    const asset = await repo.createAsset({ name: "Portal", url: "https://portal.example.com", kind: "Web application", owner: "TI", authorizationId: scope.id });
    const { findings } = await repo.recordAssessment(asset.id, "M", new Date(), [{ title: "CSP ausente", severity: "high", category: "HTTP Headers", description: "d", evidence: "e", recommendation: "r", references: [] }]);
    await repo.updateFindingStatus(findings[0].id, { status: "false_positive", reason: "CSP aplicada pelo CDN." });

    const rows = await db.select().from(webhookDeliveries).where(eq(webhookDeliveries.organizationId, a.orgId)).orderBy(webhookDeliveries.createdAt);
    const byType = Object.fromEntries(rows.map(r => [r.event, r.payload.data as Record<string, unknown>]));
    expect(Object.keys(byType).sort()).toEqual(["assessment.completed", "finding.status_changed", "scope.approved", "scope.pending"]);
    expect(byType["scope.pending"]).toMatchObject({ scope: { reference: "AUT-EV", hostnames: ["*.example.com"], status: "pending" } });
    expect(JSON.stringify(byType["scope.pending"])).not.toContain("plantão");
    expect(byType["assessment.completed"]).toMatchObject({ asset: { id: asset.id, name: "Portal" }, assessment: { summary: { created: 1 } }, newFindings: [{ title: "CSP ausente", severity: "high" }] });
    expect(byType["finding.status_changed"]).toMatchObject({ finding: { id: findings[0].id, status: "false_positive", previousStatus: "open", reason: "CSP aplicada pelo CDN." }, actor: { id: a.owner.id } });
  });

  it("escopo perto do vencimento gera scope.expiring uma vez", async () => {
    const a = await org();
    await a.hooks.create({ name: "Escopos", url: "https://s.example", events: ["scope.expiring"] });
    const repo = tenantRepository(db, a.orgId, a.owner.id);
    const scope = await repo.createAuthorization({ reference: "AUT-VENCE", hostnames: ["*.example.com"], excludedHostnames: [], validFrom: null, validUntil: new Date(Date.now() + 5 * 86_400_000) });
    await repo.approveAuthorization(scope.id, { id: a.owner.id, role: "owner" });
    await housekeeping(db);
    await housekeeping(db);
    const rows = await db.select().from(webhookDeliveries).where(eq(webhookDeliveries.organizationId, a.orgId));
    expect(rows).toHaveLength(1);
    expect(rows[0].payload.data).toMatchObject({ scope: { id: scope.id, reference: "AUT-VENCE" }, daysLeft: 5 });
  });
});
