import { and, eq, inArray, isNotNull, lt, sql } from "drizzle-orm";
import { purgeExpiredSessions } from "@/lib/auth/session";
import { logger } from "@/lib/logger";
import type { RetentionSettings } from "@/lib/retention-options";
import type { Database } from "./client";
import { assessments, auditLog, authorizations, findings, mfaChallenges, organizations, ssoRequests } from "./schema";

/**
 * Retenção por organização (LGPD, art. 15 e 16: dados são eliminados quando
 * deixam de ser necessários). O Owner escolhe os prazos entre opções fixas
 * (src/lib/retention-options.ts); o worker aplica de hora em hora.
 */
export type RetentionResult = { audit: number; assessments: number; findings: number; contacts: number };

const DAY_MS = 86_400_000;
const before = (now: Date, days: number) => new Date(now.getTime() - days * DAY_MS);

export const retentionView = (org: typeof organizations.$inferSelect): RetentionSettings => ({
  auditRetentionDays: org.auditRetentionDays, assessmentRetentionDays: org.assessmentRetentionDays,
  closedFindingRetentionDays: org.closedFindingRetentionDays, scopeContactRetentionDays: org.scopeContactRetentionDays
});

/** Aplica os prazos de uma organização. A execução mais recente concluída de cada ativo é sempre mantida (base do relatório). */
export async function applyOrganizationRetention(db: Database, organizationId: string, settings: RetentionSettings, now = new Date()): Promise<RetentionResult> {
  const audit = await db.delete(auditLog)
    .where(and(eq(auditLog.organizationId, organizationId), lt(auditLog.createdAt, before(now, settings.auditRetentionDays))))
    .returning({ id: auditLog.id });

  let removedRuns: { id: string }[] = [];
  if (settings.assessmentRetentionDays) {
    const latest = sql`(select b.id from ${assessments} b where b.asset_id = ${assessments.assetId} and b.status = 'completed' order by b.finished_at desc nulls last limit 1)`;
    removedRuns = await db.delete(assessments).where(and(
      eq(assessments.organizationId, organizationId), inArray(assessments.status, ["completed", "failed"]),
      lt(sql`coalesce(${assessments.finishedAt}, ${assessments.createdAt})`, before(now, settings.assessmentRetentionDays)),
      sql`${assessments.id} is distinct from ${latest}`
    )).returning({ id: assessments.id });
  }

  let removedFindings: { id: string }[] = [];
  if (settings.closedFindingRetentionDays) {
    removedFindings = await db.delete(findings).where(and(
      eq(findings.organizationId, organizationId), inArray(findings.status, ["fixed", "false_positive"]),
      lt(sql`coalesce(${findings.statusChangedAt}, ${findings.lastSeenAt})`, before(now, settings.closedFindingRetentionDays))
    )).returning({ id: findings.id });
  }

  // least() ignora null: o escopo terminou na revogação ou no vencimento, o que vier antes.
  const contacts = await db.update(authorizations).set({ emergencyContact: null }).where(and(
    eq(authorizations.organizationId, organizationId), isNotNull(authorizations.emergencyContact),
    lt(sql`least(${authorizations.revokedAt}, ${authorizations.validUntil})`, before(now, settings.scopeContactRetentionDays))
  )).returning({ id: authorizations.id });

  const result = { audit: audit.length, assessments: removedRuns.length, findings: removedFindings.length, contacts: contacts.length };
  // A própria limpeza fica na trilha (sem os dados apagados, só as contagens).
  if (Object.values(result).some(n => n > 0)) {
    await db.insert(auditLog).values({ organizationId, actorUserId: null, action: "organization.retention_applied", targetType: "organization", targetId: organizationId, metadata: { ...result, settings }, createdAt: now });
  }
  return result;
}

/** Todas as organizações, mais sessões, desafios MFA e logins SSO vencidos. */
export async function applyRetention(db: Database, now = new Date()) {
  await purgeExpiredSessions(db, now);
  await db.delete(mfaChallenges).where(lt(mfaChallenges.expiresAt, now));
  await db.delete(ssoRequests).where(lt(ssoRequests.expiresAt, now));
  const orgs = await db.select().from(organizations);
  for (const org of orgs) {
    try {
      const result = await applyOrganizationRetention(db, org.id, retentionView(org), now);
      if (Object.values(result).some(n => n > 0)) logger.info("retention.applied", { organizationId: org.id, ...result });
    } catch (error) {
      logger.error("retention.failed", { organizationId: org.id, error });
    }
  }
}
