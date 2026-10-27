import { and, desc, eq, inArray, like, lt, type Column, type SQL } from "drizzle-orm";
import { z } from "zod";
import type { Asset, Assessment, Finding } from "@/lib/types";
import type { Database } from "./client";
import { assessments, assets, auditLog, findings, users } from "./schema";

type NewAsset = Omit<Asset, "id" | "createdAt">;
type NewFinding = Omit<Finding, "id" | "assetId" | "discoveredAt">;
export type AuditEntry = { id: string; seq: number; action: string; targetType: string; targetId: string | null; actorUserId: string | null; actorName: string | null; actorEmail: string | null; metadata: Record<string, unknown>; createdAt: string };
export type AuditQuery = { before?: number; actionPrefix?: string };

const isUuid = (value: string) => z.uuid().safeParse(value).success;

const toAsset = (row: typeof assets.$inferSelect): Asset => ({ id: row.id, name: row.name, url: row.url, kind: row.kind, owner: row.owner, approved: row.approved, authorizationRef: row.authorizationRef, createdAt: row.createdAt.toISOString() });
const toFinding = (row: typeof findings.$inferSelect): Finding => ({ id: row.id, assetId: row.assetId, title: row.title, severity: row.severity, category: row.category, description: row.description, evidence: row.evidence, recommendation: row.recommendation, references: row.references, discoveredAt: row.discoveredAt.toISOString() });

/**
 * Único ponto de acesso a dados de negócio. Cada instância é presa a uma
 * organização e todas as consultas e escritas filtram por organization_id,
 * de modo que um tenant nunca lê nem altera registros de outro.
 */
export function tenantRepository(db: Database, organizationId: string, actorUserId: string | null = null) {
  const own = (table: { organizationId: Column }) => eq(table.organizationId, organizationId);

  async function findingIdsFor(runIds: string[]) {
    if (!runIds.length) return new Map<string, string[]>();
    const rows = await db.select({ id: findings.id, assessmentId: findings.assessmentId }).from(findings).where(and(own(findings), inArray(findings.assessmentId, runIds)));
    const map = new Map<string, string[]>(runIds.map(id => [id, []]));
    for (const row of rows) if (row.assessmentId) map.get(row.assessmentId)?.push(row.id);
    return map;
  }

  return {
    organizationId,

    async listAssets(): Promise<Asset[]> {
      return (await db.select().from(assets).where(own(assets)).orderBy(desc(assets.createdAt))).map(toAsset);
    },

    async getAsset(id: string): Promise<Asset | undefined> {
      if (!isUuid(id)) return undefined;
      const [row] = await db.select().from(assets).where(and(own(assets), eq(assets.id, id)));
      return row && toAsset(row);
    },

    async createAsset(input: NewAsset): Promise<Asset> {
      const [row] = await db.insert(assets).values({ ...input, organizationId }).returning();
      await this.audit("asset.created", "asset", row.id, { url: row.url, authorizationRef: row.authorizationRef, approved: row.approved });
      return toAsset(row);
    },

    async listFindings(): Promise<Finding[]> {
      return (await db.select().from(findings).where(own(findings)).orderBy(desc(findings.discoveredAt))).map(toFinding);
    },

    async listAssessments(): Promise<Assessment[]> {
      const rows = await db.select().from(assessments).where(and(own(assessments), eq(assessments.status, "completed"))).orderBy(desc(assessments.startedAt));
      const ids = await findingIdsFor(rows.map(r => r.id));
      return rows.map(r => ({ id: r.id, assetId: r.assetId, status: "completed" as const, startedAt: r.startedAt.toISOString(), findingIds: ids.get(r.id) ?? [] }));
    },

    /** Grava a execução concluída e seus achados atomicamente. */
    async recordAssessment(assetId: string, method: string, startedAt: Date, newFindings: NewFinding[]) {
      const asset = await this.getAsset(assetId);
      if (!asset) throw new Error("Ativo não encontrado.");
      const result = await db.transaction(async tx => {
        const [run] = await tx.insert(assessments).values({ organizationId, assetId, status: "completed", method, startedAt, finishedAt: new Date() }).returning();
        const rows = newFindings.length ? await tx.insert(findings).values(newFindings.map(f => ({ ...f, organizationId, assetId, assessmentId: run.id }))).returning() : [];
        await tx.insert(auditLog).values({ organizationId, actorUserId, action: "assessment.completed", targetType: "asset", targetId: assetId, metadata: { assessmentId: run.id, findings: rows.length, method } });
        return { run, rows };
      });
      const run: Assessment = { id: result.run.id, assetId, status: "completed", startedAt: result.run.startedAt.toISOString(), findingIds: result.rows.map(r => r.id) };
      return { run, findings: result.rows.map(toFinding) };
    },

    async latestCompletedAssessment(assetId: string) {
      if (!isUuid(assetId)) return undefined;
      const [run] = await db.select().from(assessments).where(and(own(assessments), eq(assessments.assetId, assetId), eq(assessments.status, "completed"))).orderBy(desc(assessments.startedAt)).limit(1);
      if (!run) return undefined;
      const rows = await db.select().from(findings).where(and(own(findings), eq(findings.assessmentId, run.id))).orderBy(desc(findings.discoveredAt));
      return { run: { id: run.id, assetId, status: "completed" as const, startedAt: run.startedAt.toISOString(), findingIds: rows.map(r => r.id) }, findings: rows.map(toFinding) };
    },

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
