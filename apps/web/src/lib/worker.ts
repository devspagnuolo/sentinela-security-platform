import { and, asc, eq, gt, isNotNull, isNull, lt, lte, sql } from "drizzle-orm";
import type { Database } from "@/db/client";
import { notify, pruneNotifications, sendPendingEmails } from "@/db/notifications";
import { scopeEvent, tenantRepository } from "@/db/repository";
import { syncDueConnectors } from "@/db/connectors";
import { applyRetention } from "@/db/retention";
import { drainDeliveries, emitEvent, pruneDeliveries } from "@/db/webhooks";
import { assessments, assets, authorizations, findings } from "@/db/schema";
import { logger } from "./logger";
import { mailSettings } from "./mail";
import { assess as runScanner, SCANNER_METHOD_ID, TransientAssessmentError } from "./scanner";
import type { Asset } from "./types";

/**
 * Worker de avaliações. A fila é a própria tabela assessments: o worker pega
 * jobs "queued" com FOR UPDATE SKIP LOCKED, então várias instâncias da aplicação
 * podem rodar o worker ao mesmo tempo sem processar o mesmo job duas vezes.
 * O escopo é conferido de novo no momento da execução, não só ao enfileirar.
 */
export type WorkerDeps = { assess?: (asset: Asset) => Promise<Awaited<ReturnType<typeof runScanner>>>; now?: () => Date };

export const MAX_ATTEMPTS = 3;
export const STALE_AFTER_MS = 10 * 60_000;
export const RETRY_BASE_MS = 60_000;
export const SCOPE_EXPIRY_WARNING_DAYS = 14;
const DAY_MS = 86_400_000;

type Run = typeof assessments.$inferSelect;

/** Pega o próximo job vencido e o marca como running (atômico entre instâncias). */
export async function claimNext(db: Database, now = new Date()): Promise<Run | undefined> {
  const next = db.select({ id: assessments.id }).from(assessments)
    .where(and(eq(assessments.status, "queued"), lte(assessments.runAfter, now)))
    .orderBy(asc(assessments.runAfter)).limit(1).for("update", { skipLocked: true });
  const [run] = await db.update(assessments).set({ status: "running", startedAt: now, lockedAt: now, attempts: sql`${assessments.attempts} + 1` })
    // "= (subconsulta)" vira InitPlan, avaliada uma única vez; com IN o Postgres pode reavaliá-la por linha e pegar vários jobs.
    .where(and(eq(assessments.id, sql`(${next})`), eq(assessments.status, "queued"))).returning();
  return run;
}

/** Jobs que ficaram em running (processo reiniciado no meio) voltam para a fila, ou falham após MAX_ATTEMPTS. */
export async function recoverStale(db: Database, now = new Date()) {
  const stale = await db.select().from(assessments).where(and(eq(assessments.status, "running"), lt(assessments.lockedAt, new Date(now.getTime() - STALE_AFTER_MS))));
  for (const run of stale) {
    if (run.attempts < MAX_ATTEMPTS) await db.update(assessments).set({ status: "queued", lockedAt: null, runAfter: now }).where(and(eq(assessments.id, run.id), eq(assessments.status, "running")));
    else await tenantRepository(db, run.organizationId, run.requestedBy).failAssessment(run.id, "Execução interrompida repetidamente.", now);
  }
  return stale.length;
}

/** Enfileira os ativos com reavaliação agendada vencida e já marca a próxima data. */
export async function scheduleDue(db: Database, now = new Date()) {
  const due = await db.update(assets).set({ nextAssessmentAt: sql`${now.toISOString()}::timestamptz + make_interval(days => ${assets.scheduleIntervalDays})` })
    .where(and(isNotNull(assets.scheduleIntervalDays), lte(assets.nextAssessmentAt, now)))
    .returning({ id: assets.id, organizationId: assets.organizationId });
  for (const asset of due) await tenantRepository(db, asset.organizationId).queueAssessment(asset.id, { method: SCANNER_METHOD_ID, trigger: "scheduled", now });
  return due.length;
}

/** Tarefas periódicas: aceites de risco vencidos, escopos perto do fim e limpeza de avisos lidos e entregas antigas. */
export async function housekeeping(db: Database, now = new Date()) {
  const orgs = await db.selectDistinct({ id: findings.organizationId }).from(findings).where(and(eq(findings.status, "accepted"), lt(findings.acceptedUntil, now)));
  for (const org of orgs) await tenantRepository(db, org.id).expireAcceptances(now);

  const expiring = await db.update(authorizations).set({ expiryNotifiedAt: now })
    .where(and(eq(authorizations.status, "approved"), isNull(authorizations.expiryNotifiedAt), isNotNull(authorizations.validUntil),
      lte(authorizations.validUntil, new Date(now.getTime() + SCOPE_EXPIRY_WARNING_DAYS * DAY_MS)), gt(authorizations.validUntil, now)))
    .returning();
  for (const scope of expiring) {
    const days = Math.max(1, Math.ceil((scope.validUntil!.getTime() - now.getTime()) / DAY_MS));
    await notify(db, scope.organizationId, { audience: "managers" }, {
      kind: "scope.expiring", link: "/escopos", title: `Escopo ${scope.reference} vence em ${days} dia(s)`,
      body: "Depois do vencimento, os ativos vinculados não podem mais ser avaliados. Renove a autorização com o cliente se o trabalho continua."
    });
    await emitEvent(db, scope.organizationId, "scope.expiring", { scope: scopeEvent({ ...scope, clientName: null, validFrom: scope.validFrom?.toISOString() ?? null, validUntil: scope.validUntil!.toISOString() }), daysLeft: days }, now);
  }
  await pruneNotifications(db, now);
  await pruneDeliveries(db, now);
}

/** Executa um job já marcado como running: confere o escopo, roda o scanner e grava o resultado. */
export async function processRun(db: Database, run: Run, deps: WorkerDeps = {}) {
  const now = () => deps.now?.() ?? new Date();
  const repo = tenantRepository(db, run.organizationId, run.requestedBy);
  const asset = await repo.getAsset(run.assetId);
  if (!asset) return repo.failAssessment(run.id, "Ativo não encontrado.", now());
  if (!asset.scopeOk) {
    const reason = asset.scopeMessage ?? "Ativo fora do escopo autorizado.";
    await repo.audit("assessment.blocked", "asset", asset.id, { reason, authorizationId: asset.authorizationId, assessmentId: run.id, trigger: run.trigger });
    return repo.failAssessment(run.id, reason, now());
  }
  let observed;
  try {
    observed = await (deps.assess ?? runScanner)(asset);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Falha na avaliação.";
    if (error instanceof TransientAssessmentError && run.attempts < MAX_ATTEMPTS) {
      const retryAt = new Date(now().getTime() + RETRY_BASE_MS * 2 ** (run.attempts - 1));
      await db.update(assessments).set({ status: "queued", lockedAt: null, runAfter: retryAt, error: message }).where(eq(assessments.id, run.id));
      logger.warn("assessment.retry_scheduled", { assessmentId: run.id, attempts: run.attempts, retryAt: retryAt.toISOString() });
      return;
    }
    await repo.audit("assessment.failed", "asset", asset.id, { error: message, assessmentId: run.id, attempts: run.attempts });
    return repo.failAssessment(run.id, message, now());
  }
  await repo.completeAssessment(run.id, observed.findings, now(), observed.technologies);
}

/** Processa jobs até a fila (vencida) esvaziar, com até `concurrency` execuções em paralelo. */
export async function drainQueue(db: Database, deps: WorkerDeps = {}, concurrency = 1) {
  let processed = 0;
  const lane = async () => {
    for (let run = await claimNext(db, deps.now?.()); run; run = await claimNext(db, deps.now?.())) {
      try { await processRun(db, run, deps); } catch (error) {
        logger.error("assessment.worker_error", { assessmentId: run.id, error });
        await tenantRepository(db, run.organizationId, run.requestedBy).failAssessment(run.id, "Erro interno ao processar a avaliação.").catch(() => undefined);
      }
      processed++;
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, concurrency) }, lane));
  return processed;
}

// ---- Loop em segundo plano (iniciado por src/instrumentation.ts) -------------------

type WorkerState = { timer?: NodeJS.Timeout; running: boolean; again: boolean; stopped: boolean; lastHousekeeping: number; lastRetention: number; wake?: () => void };
const g = globalThis as typeof globalThis & { sentinelaWorker?: WorkerState };

export function workerSettings(env: NodeJS.ProcessEnv = process.env) {
  return {
    enabled: env.SENTINELA_WORKER !== "0",
    pollMs: Math.max(1000, Number(env.SENTINELA_WORKER_POLL_MS ?? 5000) || 5000),
    concurrency: Math.min(10, Math.max(1, Number(env.SENTINELA_WORKER_CONCURRENCY ?? 2) || 2))
  };
}

/** Inicia o loop (uma vez por processo). `getDb` é chamado a cada ciclo para tolerar o banco subir depois. */
export function startWorker(getDb: () => Promise<Database>, settings = workerSettings()) {
  if (!settings.enabled || g.sentinelaWorker) return;
  const state: WorkerState = { running: false, again: false, stopped: false, lastHousekeeping: 0, lastRetention: 0 };
  g.sentinelaWorker = state;
  const tick = async () => {
    if (state.stopped) return;
    // Pedido durante um ciclo em andamento: roda outro ciclo assim que este terminar.
    if (state.running) { state.again = true; return; }
    state.running = true;
    try {
      const db = await getDb();
      const now = new Date();
      await recoverStale(db, now);
      await scheduleDue(db, now);
      if (now.getTime() - state.lastHousekeeping >= 60_000) { await housekeeping(db, now); state.lastHousekeeping = now.getTime(); }
      // Prazos de retenção (LGPD) de hora em hora: apagam em lote, não precisam rodar a cada minuto.
      if (now.getTime() - state.lastRetention >= 3_600_000) { await applyRetention(db, now); state.lastRetention = now.getTime(); }
      await drainQueue(db, {}, settings.concurrency);
      // Webhooks por último: inclui os eventos que as avaliações deste ciclo acabaram de gerar.
      await drainDeliveries(db);
      if (mailSettings().enabled) await sendPendingEmails(db);
      // Conectores de nuvem: cada um sincroniza uma vez por dia (só leitura de zonas DNS).
      await syncDueConnectors(db);
    } catch (error) {
      logger.error("assessment.worker_tick_failed", { error });
    } finally {
      state.running = false;
      if (state.again) { state.again = false; void tick(); }
    }
  };
  state.wake = () => void tick();
  state.timer = setInterval(() => void tick(), settings.pollMs);
  state.timer.unref();
  process.once("SIGTERM", () => { state.stopped = true; clearInterval(state.timer); });
  logger.info("assessment.worker_started", { pollMs: settings.pollMs, concurrency: settings.concurrency });
  void tick();
}

/** Acorda o worker deste processo para não esperar o próximo ciclo (ex.: avaliação pedida agora). */
export function wakeWorker() {
  g.sentinelaWorker?.wake?.();
}
