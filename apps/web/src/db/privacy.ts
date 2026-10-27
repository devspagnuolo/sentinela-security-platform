import { and, asc, count, desc, eq, getTableColumns, or, sql } from "drizzle-orm";
import type { AnyPgColumn } from "drizzle-orm/pg-core";
import type { Database } from "./client";
import { retentionView } from "./retention";
import { ANONYMIZED_DOMAIN } from "./users";
import {
  apiTokens, assessmentFindings, assessments, assets, auditLog, authorizations, clients, findingEvents, findings, memberships,
  mfaChallenges, notifications, organizations, recoveryCodes, sessions, ssoConnections, ssoIdentities, users, webhooks
} from "./schema";

/**
 * Direitos do titular (LGPD, art. 18): acesso aos próprios dados (exportação) e
 * eliminação (anonimização). A anonimização mantém a linha do usuário, porque
 * auditoria, escopos e triagens apontam para ela, mas remove tudo que identifica a pessoa.
 */
export const PERSONAL_EXPORT_AUDIT_LIMIT = 5000;
export const ORG_EXPORT_AUDIT_LIMIT = 50_000;
export const ANONYMIZED_NAME = "Pessoa removida";
export const anonymizedEmail = (userId: string) => `removido+${userId}@${ANONYMIZED_DOMAIN}`;
// Chaves de metadados de auditoria que identificam a pessoa.
const PERSONAL_AUDIT_KEYS = ["ip", "email", "name", "userAgent"];

const iso = (d: Date | null) => d?.toISOString() ?? null;
const aboutUser = (userId: string) => or(eq(auditLog.actorUserId, userId), and(eq(auditLog.targetType, "user"), eq(auditLog.targetId, userId)));

/** Tudo que o Sentinela guarda sobre a pessoa (sem hashes, segredos nem tokens). A atividade é a da organização atual. */
export async function exportPersonalData(db: Database, userId: string, organizationId: string, now = new Date()) {
  const [user] = await db.select().from(users).where(eq(users.id, userId));
  if (!user) return undefined;
  const [orgs, userSessions, tokens, identities, inbox, activity] = await Promise.all([
    db.select({ organization: organizations.name, role: memberships.role, since: memberships.createdAt }).from(memberships)
      .innerJoin(organizations, eq(organizations.id, memberships.organizationId)).where(eq(memberships.userId, userId)).orderBy(asc(memberships.createdAt)),
    db.select().from(sessions).where(eq(sessions.userId, userId)).orderBy(desc(sessions.lastSeenAt)),
    db.select().from(apiTokens).where(eq(apiTokens.userId, userId)).orderBy(desc(apiTokens.createdAt)),
    db.select().from(ssoIdentities).where(eq(ssoIdentities.userId, userId)),
    db.select().from(notifications).where(eq(notifications.userId, userId)).orderBy(desc(notifications.createdAt)),
    db.select().from(auditLog).where(and(eq(auditLog.organizationId, organizationId), aboutUser(userId))).orderBy(desc(auditLog.seq)).limit(PERSONAL_EXPORT_AUDIT_LIMIT)
  ]);
  return {
    generatedAt: now.toISOString(),
    notice: "Dados pessoais guardados pelo Sentinela sobre você, conforme o art. 18 da LGPD. Senhas, segredos de MFA e tokens são guardados só como hash ou cifrados e não são exportados.",
    profile: {
      id: user.id, name: user.name, email: user.email, createdAt: user.createdAt.toISOString(), lastLoginAt: iso(user.lastLoginAt),
      passwordChangedAt: iso(user.passwordChangedAt), hasPassword: Boolean(user.passwordHash), mfaEnabledAt: iso(user.totpEnabledAt),
      emailNotifications: user.emailNotifications, disabled: user.disabled
    },
    memberships: orgs.map(m => ({ ...m, since: m.since.toISOString() })),
    sessions: userSessions.map(s => ({ createdAt: s.createdAt.toISOString(), lastSeenAt: s.lastSeenAt.toISOString(), expiresAt: s.expiresAt.toISOString(), authMethod: s.authMethod, ip: s.ip, userAgent: s.userAgent })),
    apiTokens: tokens.map(t => ({ name: t.name, prefix: t.prefix, role: t.role, createdAt: t.createdAt.toISOString(), expiresAt: t.expiresAt.toISOString(), lastUsedAt: iso(t.lastUsedAt), lastUsedIp: t.lastUsedIp, revokedAt: iso(t.revokedAt) })),
    ssoIdentities: identities.map(i => ({ issuer: i.issuer, subject: i.subject, createdAt: i.createdAt.toISOString() })),
    notifications: inbox.map(n => ({ kind: n.kind, title: n.title, body: n.body, link: n.link, createdAt: n.createdAt.toISOString(), readAt: iso(n.readAt), emailStatus: n.emailStatus })),
    activity: activity.map(a => ({ action: a.action, targetType: a.targetType, targetId: a.targetId, byYou: a.actorUserId === userId, metadata: a.metadata, createdAt: a.createdAt.toISOString() }))
  };
}

export class AnonymizeError extends Error {
  constructor(message: string, readonly status = 409) { super(message); }
}

/**
 * Remove os dados pessoais de quem saiu da organização. Irreversível: a conta fica
 * desativada, sem e-mail, senha, MFA, sessões, tokens, vínculos SSO nem avisos, e a
 * auditoria perde IPs e e-mails ligados à pessoa. As ações registradas continuam,
 * atribuídas a "Pessoa removida".
 */
export async function anonymizeUser(db: Database, organizationId: string, userId: string) {
  const [target] = await db.select({ user: users, role: memberships.role }).from(memberships).innerJoin(users, eq(users.id, memberships.userId))
    .where(and(eq(memberships.organizationId, organizationId), eq(memberships.userId, userId)));
  if (!target) throw new AnonymizeError("Usuário não encontrado.", 404);
  if (target.user.email.endsWith(`@${ANONYMIZED_DOMAIN}`)) throw new AnonymizeError("Esta conta já foi anonimizada.");
  const [others] = await db.select({ n: count() }).from(memberships).where(and(eq(memberships.userId, userId), sql`${memberships.organizationId} <> ${organizationId}`));
  if (Number(others?.n ?? 0) > 0) throw new AnonymizeError("A pessoa também participa de outra organização nesta instalação; peça ao operador para tratar o caso.");
  if (target.role === "owner" && !target.user.disabled) {
    const [owners] = await db.select({ n: count() }).from(memberships).innerJoin(users, eq(users.id, memberships.userId))
      .where(and(eq(memberships.organizationId, organizationId), eq(memberships.role, "owner"), eq(users.disabled, false)));
    if (Number(owners?.n ?? 0) <= 1) throw new AnonymizeError("A organização precisa manter ao menos um Owner ativo.");
  }
  const previousEmail = target.user.email.toLowerCase();
  await db.transaction(async tx => {
    await tx.update(users).set({
      email: anonymizedEmail(userId), name: ANONYMIZED_NAME, passwordHash: null, disabled: true, failedLoginCount: 0, lockedUntil: null,
      lastLoginAt: null, passwordChangedAt: null, totpSecret: null, totpPendingSecret: null, totpEnabledAt: null, totpLastStep: null, emailNotifications: false
    }).where(eq(users.id, userId));
    await tx.delete(sessions).where(eq(sessions.userId, userId));
    await tx.delete(mfaChallenges).where(eq(mfaChallenges.userId, userId));
    await tx.delete(recoveryCodes).where(eq(recoveryCodes.userId, userId));
    await tx.delete(ssoIdentities).where(eq(ssoIdentities.userId, userId));
    await tx.delete(apiTokens).where(eq(apiTokens.userId, userId));
    await tx.delete(notifications).where(eq(notifications.userId, userId));
    // Inclui eventos sem vínculo direto que guardaram o e-mail (ex.: SSO recusado).
    await tx.update(auditLog).set({ metadata: sql`${auditLog.metadata} - ${`{${PERSONAL_AUDIT_KEYS.join(",")}}`}::text[]` })
      .where(and(eq(auditLog.organizationId, organizationId), or(aboutUser(userId), sql`lower(${auditLog.metadata}->>'email') = ${previousEmail}`)));
  });
}

function without<T extends object, K extends keyof T>(columns: T, key: K): Omit<T, K> {
  const copy = { ...columns };
  delete copy[key];
  return copy;
}

/** Cópia completa dos dados da organização (portabilidade, art. 18, V), sem segredos nem hashes. */
export async function exportOrganization(db: Database, organizationId: string, now = new Date()) {
  const own = (column: AnyPgColumn) => eq(column, organizationId);
  const tokenColumns = without(getTableColumns(apiTokens), "tokenHash");
  const webhookColumns = without(getTableColumns(webhooks), "secret");
  const ssoColumns = without(getTableColumns(ssoConnections), "clientSecret");
  const [[org], members, clientRows, scopes, assetRows, runs, observed, findingRows, events, audit, hooks, tokens, [sso]] = await Promise.all([
    db.select().from(organizations).where(eq(organizations.id, organizationId)),
    db.select({ id: users.id, name: users.name, email: users.email, role: memberships.role, disabled: users.disabled, since: memberships.createdAt, lastLoginAt: users.lastLoginAt, mfaEnabledAt: users.totpEnabledAt })
      .from(memberships).innerJoin(users, eq(users.id, memberships.userId)).where(own(memberships.organizationId)).orderBy(asc(users.name)),
    db.select().from(clients).where(own(clients.organizationId)),
    db.select().from(authorizations).where(own(authorizations.organizationId)).orderBy(asc(authorizations.createdAt)),
    db.select().from(assets).where(own(assets.organizationId)).orderBy(asc(assets.createdAt)),
    db.select().from(assessments).where(own(assessments.organizationId)).orderBy(asc(assessments.createdAt)),
    db.select().from(assessmentFindings).where(own(assessmentFindings.organizationId)),
    db.select().from(findings).where(own(findings.organizationId)).orderBy(asc(findings.discoveredAt)),
    db.select().from(findingEvents).where(own(findingEvents.organizationId)).orderBy(asc(findingEvents.createdAt)),
    db.select().from(auditLog).where(own(auditLog.organizationId)).orderBy(desc(auditLog.seq)).limit(ORG_EXPORT_AUDIT_LIMIT),
    db.select(webhookColumns).from(webhooks).where(own(webhooks.organizationId)),
    db.select(tokenColumns).from(apiTokens).where(own(apiTokens.organizationId)),
    db.select(ssoColumns).from(ssoConnections).where(own(ssoConnections.organizationId))
  ]);
  if (!org) return undefined;
  return {
    generatedAt: now.toISOString(),
    organization: { id: org.id, name: org.name, slug: org.slug, requireMfa: org.requireMfa, createdAt: org.createdAt.toISOString(), retention: retentionView(org) },
    members, clients: clientRows, scopes, assets: assetRows, assessments: runs, assessmentFindings: observed, findings: findingRows, findingEvents: events,
    audit: { entries: audit, truncated: audit.length === ORG_EXPORT_AUDIT_LIMIT },
    webhooks: hooks, apiTokens: tokens, sso: sso ?? null
  };
}
