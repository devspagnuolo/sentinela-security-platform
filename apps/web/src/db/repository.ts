import { aliasedTable, and, asc, count, desc, eq, inArray, like, lt, sql, type Column, type SQL } from "drizzle-orm";
import { z } from "zod";
import { evaluateScope, findingFingerprint, SCOPE_MESSAGES, scopeState } from "@/lib/scope";
import type { Asset, Assessment, Authorization, Finding, FindingEvent, FindingStatus } from "@/lib/types";
import type { Database } from "./client";
import { assessmentFindings, assessments, assets, auditLog, authorizations, clients, findingEvents, findings, users } from "./schema";

type NewAsset = { name: string; url: string; kind: Asset["kind"]; owner: string; authorizationId: string };
type NewFinding = Pick<Finding, "title" | "severity" | "category" | "description" | "evidence" | "recommendation" | "references">;
export type NewAuthorization = { reference: string; clientName?: string; hostnames: string[]; excludedHostnames: string[]; validFrom: Date | null; validUntil: Date; emergencyContact?: string; notes?: string };
export type FindingStatusChange = { status: FindingStatus; reason?: string; acceptedUntil?: Date };
export type AuditEntry = { id: string; seq: number; action: string; targetType: string; targetId: string | null; actorUserId: string | null; actorName: string | null; actorEmail: string | null; metadata: Record<string, unknown>; createdAt: string };
export type AuditQuery = { before?: number; actionPrefix?: string };

const isUuid = (value: string) => z.uuid().safeParse(value).success;
const iso = (d: Date | null) => d?.toISOString() ?? null;

type AuthorizationRow = typeof authorizations.$inferSelect;
const scopeOf = (auth: AuthorizationRow) => ({ status: auth.status, hostnames: auth.hostnames, excludedHostnames: auth.excludedHostnames, validFrom: auth.validFrom, validUntil: auth.validUntil });

function toAsset(row: typeof assets.$inferSelect, auth: AuthorizationRow | null, now = new Date()): Asset {
  const decision = auth ? evaluateScope(scopeOf(auth), new URL(row.url).hostname, now) : null;
  return {
    id: row.id, name: row.name, url: row.url, kind: row.kind, owner: row.owner, authorizationRef: row.authorizationRef, authorizationId: row.authorizationId,
    scopeState: auth ? scopeState(scopeOf(auth), now) : null,
    scopeOk: decision?.ok ?? false,
    scopeMessage: !decision ? "Ativo sem autorização de escopo vinculada." : decision.ok ? null : SCOPE_MESSAGES[decision.reason],
    scopeValidUntil: iso(auth?.validUntil ?? null),
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
    if (expired.length) await db.insert(findingEvents).values(expired.map(f => ({ organizationId, findingId: f.id, fromStatus: "accepted" as const, toStatus: "open" as const, reason: "Prazo do aceite de risco venceu." })));
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
      return rows.map(r => toAsset(r.asset, r.auth));
    },

    async getAsset(id: string): Promise<Asset | undefined> {
      if (!isUuid(id)) return undefined;
      const [row] = await db.select({ asset: assets, auth: authorizations }).from(assets).leftJoin(authorizations, eq(authorizations.id, assets.authorizationId)).where(and(own(assets), eq(assets.id, id)));
      return row && toAsset(row.asset, row.auth);
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
      return toAsset(row, auth, now);
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

    async listAssessments(): Promise<Assessment[]> {
      const rows = await db.select().from(assessments).where(and(own(assessments), eq(assessments.status, "completed"))).orderBy(desc(assessments.startedAt));
      const ids = await findingIdsFor(rows.map(r => r.id));
      return rows.map(r => ({ id: r.id, assetId: r.assetId, status: "completed" as const, startedAt: r.startedAt.toISOString(), findingIds: ids.get(r.id) ?? [] }));
    },

    /**
     * Grava a execução e consolida os achados por impressão digital, atomicamente:
     * achado novo é criado; já conhecido é atualizado (e reaberto se estava corrigido);
     * achado aberto ou com risco aceito que não apareceu mais é marcado como corrigido.
     */
    async recordAssessment(assetId: string, method: string, startedAt: Date, observed: NewFinding[], now = new Date()) {
      const asset = await this.getAsset(assetId);
      if (!asset) throw new Error("Ativo não encontrado.");
      await expireAcceptances(now);
      const result = await db.transaction(async tx => {
        const [run] = await tx.insert(assessments).values({ organizationId, assetId, status: "completed", method, startedAt, finishedAt: now }).returning();
        const known = new Map((await tx.select().from(findings).where(and(own(findings), eq(findings.assetId, assetId)))).map(f => [f.fingerprint, f]));
        const unique = new Map(observed.map(f => [findingFingerprint(f), f]));
        const rows: (typeof findings.$inferSelect)[] = [];
        const events: (typeof findingEvents.$inferInsert)[] = [];
        let created = 0, reopened = 0, resolved = 0;
        for (const [fingerprint, f] of unique) {
          const existing = known.get(fingerprint);
          if (!existing) {
            const [row] = await tx.insert(findings).values({ ...f, organizationId, assetId, assessmentId: run.id, fingerprint, discoveredAt: now, lastSeenAt: now, lastAssessmentId: run.id }).returning();
            rows.push(row); created++;
            continue;
          }
          const reopen = existing.status === "fixed";
          const [row] = await tx.update(findings).set({
            severity: f.severity, description: f.description, evidence: f.evidence, recommendation: f.recommendation, references: f.references, lastSeenAt: now, lastAssessmentId: run.id,
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
        if (rows.length) await tx.insert(assessmentFindings).values(rows.map(r => ({ organizationId, assessmentId: run.id, findingId: r.id, evidence: r.evidence })));
        if (events.length) await tx.insert(findingEvents).values(events);
        await tx.insert(auditLog).values({ organizationId, actorUserId, action: "assessment.completed", targetType: "asset", targetId: assetId, metadata: { assessmentId: run.id, observed: rows.length, created, reopened, resolved, method } });
        return { run, rows };
      });
      const run: Assessment = { id: result.run.id, assetId, status: "completed", startedAt: result.run.startedAt.toISOString(), findingIds: result.rows.map(r => r.id) };
      return { run, findings: result.rows.map(r => toFinding(r)) };
    },

    /** Última execução concluída do ativo, com os achados que ela observou (evidência daquela execução). */
    async latestCompletedAssessment(assetId: string) {
      if (!isUuid(assetId)) return undefined;
      const [run] = await db.select().from(assessments).where(and(own(assessments), eq(assessments.assetId, assetId), eq(assessments.status, "completed"))).orderBy(desc(assessments.startedAt)).limit(1);
      if (!run) return undefined;
      const rows = await db.select({ finding: findings, evidence: assessmentFindings.evidence }).from(assessmentFindings)
        .innerJoin(findings, eq(findings.id, assessmentFindings.findingId))
        .where(and(own(assessmentFindings), eq(assessmentFindings.assessmentId, run.id))).orderBy(desc(findings.discoveredAt));
      return { run: { id: run.id, assetId, status: "completed" as const, startedAt: run.startedAt.toISOString(), findingIds: rows.map(r => r.finding.id) }, findings: rows.map(r => toFinding(r.finding, r.evidence)) };
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
