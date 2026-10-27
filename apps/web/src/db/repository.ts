import { aliasedTable, and, asc, count, desc, eq, inArray, like, lt, sql, type Column, type SQL } from "drizzle-orm";
import { z } from "zod";
import { evaluateScope, findingFingerprint, SCOPE_MESSAGES, scopeState } from "@/lib/scope";
import type { Asset, Assessment, AssessmentSummary, Authorization, Finding, FindingEvent, FindingStatus } from "@/lib/types";
import type { Database } from "./client";
import { notify } from "./notifications";
import { assessmentFindings, assessments, assets, auditLog, authorizations, clients, findingEvents, findings, users } from "./schema";

type NewAsset = { name: string; url: string; kind: Asset["kind"]; owner: string; authorizationId: string };
type NewFinding = Pick<Finding, "title" | "severity" | "category" | "description" | "evidence" | "recommendation" | "references">;
export type NewAuthorization = { reference: string; clientName?: string; hostnames: string[]; excludedHostnames: string[]; validFrom: Date | null; validUntil: Date; emergencyContact?: string; notes?: string };
export type FindingStatusChange = { status: FindingStatus; reason?: string; acceptedUntil?: Date };
export type AuditEntry = { id: string; seq: number; action: string; targetType: string; targetId: string | null; actorUserId: string | null; actorName: string | null; actorEmail: string | null; metadata: Record<string, unknown>; createdAt: string };
export type AuditQuery = { before?: number; actionPrefix?: string };
export type QueueOptions = { method: string; trigger?: Assessment["trigger"]; now?: Date };
/** Intervalos de reavaliação oferecidos (dias). */
export const SCHEDULE_INTERVALS = [1, 7, 30] as const;

const isUuid = (value: string) => z.uuid().safeParse(value).success;
const iso = (d: Date | null) => d?.toISOString() ?? null;

type AuthorizationRow = typeof authorizations.$inferSelect;
type AssessmentRow = typeof assessments.$inferSelect;
const DAY_MS = 86_400_000;
const scopeOf = (auth: AuthorizationRow) => ({ status: auth.status, hostnames: auth.hostnames, excludedHostnames: auth.excludedHostnames, validFrom: auth.validFrom, validUntil: auth.validUntil });

const toAssessment = (r: AssessmentRow, extra: { requesterName?: string | null; assetName?: string; findingIds?: string[] } = {}): Assessment => ({
  id: r.id, assetId: r.assetId, ...(extra.assetName !== undefined && { assetName: extra.assetName }), status: r.status, trigger: r.trigger, method: r.method,
  requestedBy: r.requestedBy ? { id: r.requestedBy, name: extra.requesterName ?? "—" } : null,
  attempts: r.attempts, error: r.error, summary: r.summary ?? null,
  createdAt: r.createdAt.toISOString(), startedAt: iso(r.startedAt), finishedAt: iso(r.finishedAt), findingIds: extra.findingIds ?? []
});

function toAsset(row: typeof assets.$inferSelect, auth: AuthorizationRow | null, last: AssessmentRow | null = null, now = new Date()): Asset {
  const decision = auth ? evaluateScope(scopeOf(auth), new URL(row.url).hostname, now) : null;
  return {
    id: row.id, name: row.name, url: row.url, kind: row.kind, owner: row.owner, authorizationRef: row.authorizationRef, authorizationId: row.authorizationId,
    scopeState: auth ? scopeState(scopeOf(auth), now) : null,
    scopeOk: decision?.ok ?? false,
    scopeMessage: !decision ? "Ativo sem autorização de escopo vinculada." : decision.ok ? null : SCOPE_MESSAGES[decision.reason],
    scopeValidUntil: iso(auth?.validUntil ?? null),
    scheduleIntervalDays: row.scheduleIntervalDays, nextAssessmentAt: iso(row.nextAssessmentAt),
    lastAssessment: last && { id: last.id, status: last.status, error: last.error, createdAt: last.createdAt.toISOString(), finishedAt: iso(last.finishedAt) },
    createdAt: row.createdAt.toISOString()
  };
}

const toFinding = (row: typeof findings.$inferSelect, evidence?: string): Finding => ({
  id: row.id, assetId: row.assetId, title: row.title, severity: row.severity, category: row.category, description: row.description,
  evidence: evidence ?? row.evidence, recommendation: row.recommendation, references: row.references,
  status: row.status, statusReason: row.statusReason, statusChangedAt: iso(row.statusChangedAt), acceptedUntil: iso(row.acceptedUntil),
  discoveredAt: row.discoveredAt.toISOString(), lastSeenAt: row.lastSeenAt.toISOString()
});

export class RepositoryError extends Error {
  constructor(message: string, readonly status: number) { super(message); }
}

/**
 * Único ponto de acesso a dados de negócio. Cada instância é presa a uma
 * organização e todas as consultas e escritas filtram por organization_id,
 * de modo que um tenant nunca lê nem altera registros de outro.
 */
export function tenantRepository(db: Database, organizationId: string, actorUserId: string | null = null) {
  const own = (table: { organizationId: Column }) => eq(table.organizationId, organizationId);

  async function findingIdsFor(runIds: string[]) {
    if (!runIds.length) return new Map<string, string[]>();
    const rows = await db.select({ assessmentId: assessmentFindings.assessmentId, findingId: assessmentFindings.findingId }).from(assessmentFindings).where(and(own(assessmentFindings), inArray(assessmentFindings.assessmentId, runIds)));
    const map = new Map<string, string[]>(runIds.map(id => [id, []]));
    for (const row of rows) map.get(row.assessmentId)?.push(row.findingId);
    return map;
  }

  /** Aceites de risco vencidos voltam a "open" (com evento no histórico). */
  async function expireAcceptances(now = new Date()) {
    const expired = await db.update(findings).set({ status: "open", statusReason: "Prazo do aceite de risco venceu.", statusChangedAt: now, statusChangedBy: null, acceptedUntil: null })
      .where(and(own(findings), eq(findings.status, "accepted"), lt(findings.acceptedUntil, now))).returning({ id: findings.id });
    if (!expired.length) return 0;
    await db.insert(findingEvents).values(expired.map(f => ({ organizationId, findingId: f.id, fromStatus: "accepted" as const, toStatus: "open" as const, reason: "Prazo do aceite de risco venceu." })));
    await notify(db, organizationId, { audience: "managers" }, {
      kind: "finding.acceptance_expired", link: "/achados",
      title: expired.length === 1 ? "Um aceite de risco venceu" : `${expired.length} aceites de risco venceram`,
      body: "Os achados voltaram a ficar abertos e precisam de nova decisão."
    });
    return expired.length;
  }

  /** Última execução (de qualquer situação) de cada ativo. */
  async function latestRuns(assetIds: string[]) {
    if (!assetIds.length) return new Map<string, AssessmentRow>();
    const rows = await db.selectDistinctOn([assessments.assetId]).from(assessments)
      .where(and(own(assessments), inArray(assessments.assetId, assetIds))).orderBy(assessments.assetId, desc(assessments.createdAt));
    return new Map(rows.map(r => [r.assetId, r]));
  }

  /**
   * Consolida os achados de uma execução por impressão digital, dentro da transação:
   * achado novo é criado; já conhecido é atualizado (e reaberto se estava corrigido);
   * achado aberto ou com risco aceito que não apareceu mais é marcado como corrigido.
   */
  async function consolidate(tx: Database, runId: string, assetId: string, observed: NewFinding[], now: Date) {
    const known = new Map((await tx.select().from(findings).where(and(own(findings), eq(findings.assetId, assetId)))).map(f => [f.fingerprint, f]));
    const unique = new Map(observed.map(f => [findingFingerprint(f), f]));
    const rows: (typeof findings.$inferSelect)[] = [];
    const events: (typeof findingEvents.$inferInsert)[] = [];
    const urgent: string[] = [];
    let created = 0, reopened = 0, resolved = 0;
    for (const [fingerprint, f] of unique) {
      const existing = known.get(fingerprint);
      if (!existing) {
        const [row] = await tx.insert(findings).values({ ...f, organizationId, assetId, assessmentId: runId, fingerprint, discoveredAt: now, lastSeenAt: now, lastAssessmentId: runId }).returning();
        rows.push(row); created++;
        if (f.severity === "critical" || f.severity === "high") urgent.push(f.title);
        continue;
      }
      const reopen = existing.status === "fixed";
      const [row] = await tx.update(findings).set({
        severity: f.severity, description: f.description, evidence: f.evidence, recommendation: f.recommendation, references: f.references, lastSeenAt: now, lastAssessmentId: runId,
        ...(reopen && { status: "open" as const, statusReason: "Observado novamente na reavaliação.", statusChangedAt: now, statusChangedBy: null })
      }).where(eq(findings.id, existing.id)).returning();
      if (reopen) { events.push({ organizationId, findingId: existing.id, fromStatus: "fixed", toStatus: "open", reason: "Observado novamente na reavaliação.", createdAt: now }); reopened++; }
      rows.push(row);
    }
    for (const [fingerprint, f] of known) {
      if (unique.has(fingerprint) || (f.status !== "open" && f.status !== "accepted")) continue;
      await tx.update(findings).set({ status: "fixed", statusReason: "Não observado na reavaliação.", statusChangedAt: now, statusChangedBy: null, acceptedUntil: null }).where(eq(findings.id, f.id));
      events.push({ organizationId, findingId: f.id, fromStatus: f.status, toStatus: "fixed", reason: "Não observado na reavaliação.", createdAt: now });
      resolved++;
    }
    if (rows.length) await tx.insert(assessmentFindings).values(rows.map(r => ({ organizationId, assessmentId: runId, findingId: r.id, evidence: r.evidence })));
    if (events.length) await tx.insert(findingEvents).values(events);
    const summary: AssessmentSummary = { observed: rows.length, created, reopened, resolved };
    return { rows, summary, urgent };
  }

  /** Avisa a operação quando a execução trouxe algo que pede ação (achado alto/crítico novo ou reaberto). */
  async function notifyOutcome(asset: Asset, summary: AssessmentSummary, urgent: string[]) {
    if (!urgent.length && !summary.reopened) return;
    const parts = [urgent.length && `${urgent.length} achado(s) novo(s) de severidade alta ou crítica`, summary.reopened && `${summary.reopened} achado(s) reaberto(s)`].filter(Boolean);
    await notify(db, organizationId, { audience: "operators" }, {
      kind: "assessment.attention", link: "/achados", title: `${asset.name}: ${parts.join(" e ")}`,
      body: urgent.length ? urgent.slice(0, 5).join("; ") : "Problemas marcados como corrigidos foram observados novamente."
    });
  }

  const creator = aliasedTable(users, "creator");
  const approver = aliasedTable(users, "approver");

  function toAuthorization(row: { auth: AuthorizationRow; clientName: string | null; creatorName: string | null; approverName: string | null; assetCount: number }, now = new Date()): Authorization {
    const a = row.auth;
    return {
      id: a.id, reference: a.reference, clientName: row.clientName, hostnames: a.hostnames, excludedHostnames: a.excludedHostnames,
      validFrom: iso(a.validFrom), validUntil: iso(a.validUntil), emergencyContact: a.emergencyContact, notes: a.exclusions,
      status: a.status, state: scopeState(scopeOf(a), now),
      createdBy: a.createdBy ? { id: a.createdBy, name: row.creatorName ?? "—" } : null,
      approvedBy: a.approvedBy ? { id: a.approvedBy, name: row.approverName ?? "—" } : null,
      approvedAt: iso(a.approvedAt), revokedAt: iso(a.revokedAt), revokeReason: a.revokeReason, assetCount: Number(row.assetCount), createdAt: a.createdAt.toISOString()
    };
  }

  async function selectAuthorizations(where: SQL) {
    const assetCount = db.$with("asset_count").as(db.select({ authorizationId: assets.authorizationId, n: count().as("n") }).from(assets).where(own(assets)).groupBy(assets.authorizationId));
    return db.with(assetCount).select({ auth: authorizations, clientName: clients.name, creatorName: creator.name, approverName: approver.name, assetCount: sql<number>`coalesce(${assetCount.n}, 0)` })
      .from(authorizations)
      .leftJoin(clients, eq(clients.id, authorizations.clientId))
      .leftJoin(creator, eq(creator.id, authorizations.createdBy))
      .leftJoin(approver, eq(approver.id, authorizations.approvedBy))
      .leftJoin(assetCount, eq(assetCount.authorizationId, authorizations.id))
      .where(where).orderBy(desc(authorizations.createdAt));
  }

  return {
    organizationId,
    expireAcceptances,

    // ---- Autorizações de escopo -------------------------------------------------

    async listAuthorizations(): Promise<Authorization[]> {
      return (await selectAuthorizations(own(authorizations))).map(r => toAuthorization(r));
    },

    async getAuthorization(id: string): Promise<Authorization | undefined> {
      if (!isUuid(id)) return undefined;
      const [row] = await selectAuthorizations(and(own(authorizations), eq(authorizations.id, id))!);
      return row && toAuthorization(row);
    },

    async createAuthorization(input: NewAuthorization): Promise<Authorization> {
      const id = await db.transaction(async tx => {
        let clientId: string | null = null;
        const clientName = input.clientName?.trim();
        if (clientName) {
          const [existing] = await tx.select({ id: clients.id }).from(clients).where(and(own(clients), sql`lower(${clients.name}) = ${clientName.toLowerCase()}`));
          clientId = existing?.id ?? (await tx.insert(clients).values({ organizationId, name: clientName }).returning({ id: clients.id }))[0].id;
        }
        const [row] = await tx.insert(authorizations).values({
          organizationId, clientId, reference: input.reference, hostnames: input.hostnames, excludedHostnames: input.excludedHostnames,
          validFrom: input.validFrom, validUntil: input.validUntil, emergencyContact: input.emergencyContact || null, exclusions: input.notes || null, createdBy: actorUserId
        }).returning({ id: authorizations.id });
        return row.id;
      });
      await this.audit("scope.created", "authorization", id, { reference: input.reference, hostnames: input.hostnames, excludedHostnames: input.excludedHostnames, validFrom: iso(input.validFrom), validUntil: iso(input.validUntil) });
      await notify(db, organizationId, { audience: "managers", exclude: actorUserId }, {
        kind: "scope.pending", link: "/escopos", title: `Escopo ${input.reference} aguarda aprovação`, body: input.hostnames.join(", ")
      });
      return (await this.getAuthorization(id))!;
    },

    /**
     * Aprovação por outra pessoa (quatro olhos). O Owner pode aprovar o que ele
     * mesmo cadastrou, para consultorias com uma só pessoa na gestão; fica registrado.
     */
    async approveAuthorization(id: string, approver: { id: string; role: string }, now = new Date()): Promise<Authorization> {
      const current = await this.getAuthorization(id);
      if (!current) throw new RepositoryError("Autorização não encontrada.", 404);
      if (current.status !== "pending") throw new RepositoryError("Somente autorizações pendentes podem ser aprovadas.", 409);
      const selfApproved = current.createdBy?.id === approver.id;
      if (selfApproved && approver.role !== "owner") throw new RepositoryError("A aprovação precisa ser feita por outra pessoa (Admin ou Owner).", 403);
      if (current.validUntil && new Date(current.validUntil) < now) throw new RepositoryError("A janela desta autorização já terminou.", 409);
      await db.update(authorizations).set({ status: "approved", approvedBy: approver.id, approvedAt: now }).where(and(own(authorizations), eq(authorizations.id, id), eq(authorizations.status, "pending")));
      await this.audit("scope.approved", "authorization", id, { reference: current.reference, selfApproved });
      return (await this.getAuthorization(id))!;
    },

    async revokeAuthorization(id: string, reason: string, now = new Date()): Promise<Authorization> {
      const current = await this.getAuthorization(id);
      if (!current) throw new RepositoryError("Autorização não encontrada.", 404);
      if (current.status === "revoked") throw new RepositoryError("A autorização já está revogada.", 409);
      await db.update(authorizations).set({ status: "revoked", revokedBy: actorUserId, revokedAt: now, revokeReason: reason }).where(and(own(authorizations), eq(authorizations.id, id)));
      await this.audit("scope.revoked", "authorization", id, { reference: current.reference, reason });
      return (await this.getAuthorization(id))!;
    },

    // ---- Ativos -----------------------------------------------------------------

    async listAssets(): Promise<Asset[]> {
      const rows = await db.select({ asset: assets, auth: authorizations }).from(assets).leftJoin(authorizations, eq(authorizations.id, assets.authorizationId)).where(own(assets)).orderBy(desc(assets.createdAt));
      const last = await latestRuns(rows.map(r => r.asset.id));
      return rows.map(r => toAsset(r.asset, r.auth, last.get(r.asset.id)));
    },

    async getAsset(id: string): Promise<Asset | undefined> {
      if (!isUuid(id)) return undefined;
      const [row] = await db.select({ asset: assets, auth: authorizations }).from(assets).leftJoin(authorizations, eq(authorizations.id, assets.authorizationId)).where(and(own(assets), eq(assets.id, id)));
      return row && toAsset(row.asset, row.auth, (await latestRuns([row.asset.id])).get(row.asset.id));
    },

    /** Cadastra o ativo sob uma autorização aprovada e não vencida que cubra o hostname. */
    async createAsset(input: NewAsset, now = new Date()): Promise<Asset> {
      if (!isUuid(input.authorizationId)) throw new RepositoryError("Selecione uma autorização de escopo.", 400);
      const [auth] = await db.select().from(authorizations).where(and(own(authorizations), eq(authorizations.id, input.authorizationId)));
      if (!auth) throw new RepositoryError("Autorização de escopo não encontrada.", 400);
      const decision = evaluateScope(scopeOf(auth), new URL(input.url).hostname, now);
      if (!decision.ok && decision.reason !== "not_started") throw new RepositoryError(SCOPE_MESSAGES[decision.reason], 400);
      const [row] = await db.insert(assets).values({ ...input, organizationId, authorizationRef: auth.reference }).returning();
      await this.audit("asset.created", "asset", row.id, { url: row.url, authorizationId: auth.id, authorizationRef: auth.reference });
      return toAsset(row, auth, null, now);
    },

    /** Liga (intervalo em dias) ou desliga (null) a reavaliação periódica; a primeira roda após um intervalo. */
    async setSchedule(assetId: string, intervalDays: number | null, now = new Date()): Promise<Asset> {
      const asset = await this.getAsset(assetId);
      if (!asset) throw new RepositoryError("Ativo não encontrado.", 404);
      await db.update(assets).set({ scheduleIntervalDays: intervalDays, nextAssessmentAt: intervalDays ? new Date(now.getTime() + intervalDays * DAY_MS) : null })
        .where(and(own(assets), eq(assets.id, assetId)));
      await this.audit("asset.schedule_updated", "asset", assetId, { intervalDays, previous: asset.scheduleIntervalDays });
      return (await this.getAsset(assetId))!;
    },

    // ---- Achados ----------------------------------------------------------------

    async listFindings(filter: { status?: FindingStatus[]; assetId?: string } = {}): Promise<Finding[]> {
      await expireAcceptances();
      const conditions: SQL[] = [own(findings)];
      if (filter.status?.length) conditions.push(inArray(findings.status, filter.status));
      if (filter.assetId) { if (!isUuid(filter.assetId)) return []; conditions.push(eq(findings.assetId, filter.assetId)); }
      return (await db.select().from(findings).where(and(...conditions)).orderBy(desc(findings.lastSeenAt))).map(r => toFinding(r));
    },

    async getFinding(id: string): Promise<Finding | undefined> {
      if (!isUuid(id)) return undefined;
      const [row] = await db.select().from(findings).where(and(own(findings), eq(findings.id, id)));
      return row && toFinding(row);
    },

    async listFindingEvents(findingId: string): Promise<FindingEvent[]> {
      if (!isUuid(findingId)) return [];
      const rows = await db.select({ e: findingEvents, actorName: users.name }).from(findingEvents).leftJoin(users, eq(users.id, findingEvents.actorUserId))
        .where(and(own(findingEvents), eq(findingEvents.findingId, findingId))).orderBy(asc(findingEvents.createdAt));
      return rows.map(({ e, actorName }) => ({ id: e.id, fromStatus: e.fromStatus, toStatus: e.toStatus, reason: e.reason, actorName, createdAt: e.createdAt.toISOString() }));
    },

    /** Triagem manual; as regras de quem pode o quê ficam na rota (permissões). */
    async updateFindingStatus(id: string, change: FindingStatusChange, now = new Date()): Promise<Finding> {
      const current = await this.getFinding(id);
      if (!current) throw new RepositoryError("Achado não encontrado.", 404);
      if (current.status === change.status && change.status !== "accepted") throw new RepositoryError("O achado já está nesta situação.", 409);
      const [row] = await db.update(findings).set({
        status: change.status, statusReason: change.reason?.trim() || null, statusChangedAt: now, statusChangedBy: actorUserId,
        acceptedUntil: change.status === "accepted" ? change.acceptedUntil ?? null : null
      }).where(and(own(findings), eq(findings.id, id))).returning();
      await db.insert(findingEvents).values({ organizationId, findingId: id, actorUserId, fromStatus: current.status, toStatus: change.status, reason: change.reason?.trim() || null, createdAt: now });
      await this.audit("finding.status_changed", "finding", id, { from: current.status, to: change.status, reason: change.reason ?? null, acceptedUntil: iso(change.acceptedUntil ?? null) });
      return toFinding(row);
    },

    // ---- Avaliações -------------------------------------------------------------

    /** Execuções mais recentes (todas as situações), opcionalmente de um ativo. */
    async listAssessments(filter: { assetId?: string; limit?: number } = {}): Promise<Assessment[]> {
      const conditions: SQL[] = [own(assessments)];
      if (filter.assetId) { if (!isUuid(filter.assetId)) return []; conditions.push(eq(assessments.assetId, filter.assetId)); }
      const rows = await db.select({ run: assessments, requesterName: users.name, assetName: assets.name }).from(assessments)
        .innerJoin(assets, eq(assets.id, assessments.assetId)).leftJoin(users, eq(users.id, assessments.requestedBy))
        .where(and(...conditions)).orderBy(desc(assessments.createdAt)).limit(Math.min(Math.max(filter.limit ?? 100, 1), 500));
      const ids = await findingIdsFor(rows.filter(r => r.run.status === "completed").map(r => r.run.id));
      return rows.map(r => toAssessment(r.run, { requesterName: r.requesterName, assetName: r.assetName, findingIds: ids.get(r.run.id) }));
    },

    async getAssessment(id: string): Promise<Assessment | undefined> {
      if (!isUuid(id)) return undefined;
      const [row] = await db.select({ run: assessments, requesterName: users.name, assetName: assets.name }).from(assessments)
        .innerJoin(assets, eq(assets.id, assessments.assetId)).leftJoin(users, eq(users.id, assessments.requestedBy))
        .where(and(own(assessments), eq(assessments.id, id)));
      if (!row) return undefined;
      const ids = await findingIdsFor(row.run.status === "completed" ? [row.run.id] : []);
      return toAssessment(row.run, { requesterName: row.requesterName, assetName: row.assetName, findingIds: ids.get(row.run.id) });
    },

    /**
     * Coloca a avaliação na fila do worker. Se o ativo já tem uma pendente ou em
     * execução, devolve essa (índice único parcial) em vez de criar outra.
     */
    async queueAssessment(assetId: string, options: QueueOptions): Promise<{ assessment: Assessment; queued: boolean }> {
      const asset = await this.getAsset(assetId);
      if (!asset) throw new RepositoryError("Ativo não encontrado.", 404);
      const now = options.now ?? new Date();
      const [row] = await db.insert(assessments).values({ organizationId, assetId, status: "queued", method: options.method, trigger: options.trigger ?? "manual", requestedBy: actorUserId, runAfter: now, createdAt: now })
        .onConflictDoNothing().returning({ id: assessments.id });
      if (row) {
        await this.audit("assessment.queued", "asset", assetId, { assessmentId: row.id, trigger: options.trigger ?? "manual" });
        return { assessment: (await this.getAssessment(row.id))!, queued: true };
      }
      const [active] = await db.select({ id: assessments.id }).from(assessments).where(and(own(assessments), eq(assessments.assetId, assetId), inArray(assessments.status, ["queued", "running"])));
      if (!active) throw new RepositoryError("Não foi possível enfileirar a avaliação.", 409);
      return { assessment: (await this.getAssessment(active.id))!, queued: false };
    },

    /** Conclui uma execução da fila (status running) e consolida os achados observados. */
    async completeAssessment(runId: string, observed: NewFinding[], now = new Date()) {
      const [run] = await db.select().from(assessments).where(and(own(assessments), eq(assessments.id, runId)));
      if (!run || run.status !== "running") throw new RepositoryError("Execução não está em andamento.", 409);
      const asset = await this.getAsset(run.assetId);
      if (!asset) throw new RepositoryError("Ativo não encontrado.", 404);
      await expireAcceptances(now);
      const { rows, summary, urgent } = await db.transaction(async tx => {
        const result = await consolidate(tx as unknown as Database, runId, run.assetId, observed, now);
        await tx.update(assessments).set({ status: "completed", finishedAt: now, lockedAt: null, error: null, summary: result.summary }).where(eq(assessments.id, runId));
        await tx.insert(auditLog).values({ organizationId, actorUserId, action: "assessment.completed", targetType: "asset", targetId: run.assetId, metadata: { assessmentId: runId, ...result.summary, method: run.method, trigger: run.trigger } });
        return result;
      });
      await notifyOutcome(asset, summary, urgent);
      return { run: (await this.getAssessment(runId))!, findings: rows.map(r => toFinding(r)) };
    },

    /** Encerra a execução com falha (ou bloqueio de escopo) e avisa quem pediu, ou a operação se foi agendada. */
    async failAssessment(runId: string, error: string, now = new Date()) {
      const [run] = await db.update(assessments).set({ status: "failed", error: error.slice(0, 500), finishedAt: now, lockedAt: null })
        .where(and(own(assessments), eq(assessments.id, runId))).returning();
      if (!run) return;
      const asset = await this.getAsset(run.assetId);
      await notify(db, organizationId, run.requestedBy ? { userIds: [run.requestedBy] } : { audience: "operators" }, {
        kind: "assessment.failed", link: "/avaliacoes", title: `Avaliação de ${asset?.name ?? "ativo"} não concluída`, body: error.slice(0, 300)
      });
    },

    /** Grava uma execução já feita (fora da fila: dados demonstrativos e testes) e consolida os achados. */
    async recordAssessment(assetId: string, method: string, startedAt: Date, observed: NewFinding[], now = new Date()) {
      const asset = await this.getAsset(assetId);
      if (!asset) throw new Error("Ativo não encontrado.");
      await expireAcceptances(now);
      const result = await db.transaction(async tx => {
        const [run] = await tx.insert(assessments).values({ organizationId, assetId, status: "completed", method, requestedBy: actorUserId, attempts: 1, createdAt: startedAt, startedAt, finishedAt: now }).returning();
        const consolidated = await consolidate(tx as unknown as Database, run.id, assetId, observed, now);
        await tx.update(assessments).set({ summary: consolidated.summary }).where(eq(assessments.id, run.id));
        await tx.insert(auditLog).values({ organizationId, actorUserId, action: "assessment.completed", targetType: "asset", targetId: assetId, metadata: { assessmentId: run.id, ...consolidated.summary, method } });
        return { run: { ...run, summary: consolidated.summary }, ...consolidated };
      });
      await notifyOutcome(asset, result.summary, result.urgent);
      return { run: toAssessment(result.run, { findingIds: result.rows.map(r => r.id) }), findings: result.rows.map(r => toFinding(r)) };
    },

    /** Última execução concluída do ativo, com os achados que ela observou (evidência daquela execução). */
    async latestCompletedAssessment(assetId: string) {
      if (!isUuid(assetId)) return undefined;
      const [run] = await db.select().from(assessments).where(and(own(assessments), eq(assessments.assetId, assetId), eq(assessments.status, "completed"))).orderBy(desc(assessments.finishedAt)).limit(1);
      if (!run) return undefined;
      const rows = await db.select({ finding: findings, evidence: assessmentFindings.evidence }).from(assessmentFindings)
        .innerJoin(findings, eq(findings.id, assessmentFindings.findingId))
        .where(and(own(assessmentFindings), eq(assessmentFindings.assessmentId, run.id))).orderBy(desc(findings.discoveredAt));
      return { run: toAssessment(run, { findingIds: rows.map(r => r.finding.id) }), findings: rows.map(r => toFinding(r.finding, r.evidence)) };
    },

    // ---- Auditoria --------------------------------------------------------------

    async audit(action: string, targetType: string, targetId: string | null, metadata: Record<string, unknown> = {}) {
      await db.insert(auditLog).values({ organizationId, actorUserId, action, targetType, targetId, metadata });
    },

    /** Mais recentes primeiro; `before` (seq) pagina para trás e `actionPrefix` filtra por categoria (ex.: "auth."). */
    async listAudit(limit = 100, query: AuditQuery = {}): Promise<AuditEntry[]> {
      const conditions: SQL[] = [own(auditLog)];
      if (query.before !== undefined) conditions.push(lt(auditLog.seq, query.before));
      if (query.actionPrefix) conditions.push(like(auditLog.action, `${query.actionPrefix.replace(/[%_\\]/g, "")}%`));
      const rows = await db.select({ entry: auditLog, actorName: users.name, actorEmail: users.email }).from(auditLog)
        .leftJoin(users, eq(users.id, auditLog.actorUserId))
        .where(and(...conditions)).orderBy(desc(auditLog.seq)).limit(Math.min(Math.max(limit, 1), 500));
      return rows.map(({ entry: r, actorName, actorEmail }) => ({ id: r.id, seq: r.seq, action: r.action, targetType: r.targetType, targetId: r.targetId, actorUserId: r.actorUserId, actorName, actorEmail, metadata: r.metadata, createdAt: r.createdAt.toISOString() }));
    }
  };
}

export type TenantRepository = ReturnType<typeof tenantRepository>;
