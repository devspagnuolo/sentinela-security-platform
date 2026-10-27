import { eq } from "drizzle-orm";
import { beforeAll, describe, expect, it } from "vitest";
import { createApiToken } from "@/lib/auth/tokens";
import { createSession } from "@/lib/auth/session";
import { createDatabase, type Database } from "./client";
import { ANONYMIZED_NAME, anonymizedEmail, anonymizeUser, exportOrganization, exportPersonalData } from "./privacy";
import { tenantRepository } from "./repository";
import { applyOrganizationRetention, applyRetention } from "./retention";
import { apiTokens, assessments, auditLog, authorizations, findings, memberships, notifications, organizations, sessions, ssoConnections, ssoIdentities, users, webhooks } from "./schema";
import { memberRepository } from "./users";

let db: Database;
const DAY = 86_400_000;
const now = new Date("2026-10-27T12:00:00Z");
const daysAgo = (n: number) => new Date(now.getTime() - n * DAY);
const finding = (title: string) => ({ title, severity: "low" as const, category: "HTTP Headers", description: "d", evidence: "e", recommendation: "r", references: [] });
let n = 0;

async function newOrg() {
  const [org] = await db.insert(organizations).values({ slug: `lgpd-${++n}`, name: `Org ${n}` }).returning();
  const [scope] = await db.insert(authorizations).values({ organizationId: org.id, reference: `AUT-${n}`, hostnames: ["*.example.com"], status: "approved", validUntil: new Date(now.getTime() + 30 * DAY), emergencyContact: "plantao@cliente.com.br" }).returning();
  return { org, scope, repo: tenantRepository(db, org.id) };
}
const member = (orgId: string, role: "owner" | "admin" | "viewer" = "viewer") =>
  memberRepository(db, orgId).create({ email: `pessoa${++n}@example.com`, name: `Pessoa ${n}`, role, password: "correct-horse-battery-staple" });

beforeAll(async () => {
  db = await createDatabase({ NODE_ENV: "test", SENTINELA_SEED_DEMO: "0" });
});

describe("retenção", () => {
  it("apaga auditoria antiga e registra a limpeza só com contagens", async () => {
    const { org } = await newOrg();
    await db.insert(auditLog).values([
      { organizationId: org.id, action: "auth.login_succeeded", targetType: "user", metadata: { ip: "203.0.113.9" }, createdAt: daysAgo(800) },
      { organizationId: org.id, action: "auth.login_succeeded", targetType: "user", metadata: {}, createdAt: daysAgo(10) }
    ]);
    const result = await applyOrganizationRetention(db, org.id, { auditRetentionDays: 730, assessmentRetentionDays: null, closedFindingRetentionDays: null, scopeContactRetentionDays: 180 }, now);
    expect(result).toEqual({ audit: 1, assessments: 0, findings: 0, contacts: 0 });
    const rows = await db.select().from(auditLog).where(eq(auditLog.organizationId, org.id));
    expect(rows.map(r => r.action).sort()).toEqual(["auth.login_succeeded", "organization.retention_applied"]);
    expect(rows.find(r => r.action === "organization.retention_applied")?.metadata).toMatchObject({ audit: 1 });
  });

  it("apaga execuções antigas, mas mantém a última concluída de cada ativo e os achados que elas criaram", async () => {
    const { org, scope, repo } = await newOrg();
    const asset = await repo.createAsset({ name: "Portal", url: "https://portal.example.com", kind: "Web application", owner: "TI", authorizationId: scope.id });
    const first = await repo.recordAssessment(asset.id, "M", daysAgo(400), [finding("HSTS ausente")], daysAgo(400));
    const second = await repo.recordAssessment(asset.id, "M", daysAgo(300), [finding("HSTS ausente")], daysAgo(300));
    const result = await applyOrganizationRetention(db, org.id, { auditRetentionDays: 1825, assessmentRetentionDays: 180, closedFindingRetentionDays: null, scopeContactRetentionDays: 365 }, now);
    expect(result.assessments).toBe(1);
    const runs = await db.select({ id: assessments.id }).from(assessments).where(eq(assessments.organizationId, org.id));
    expect(runs.map(r => r.id)).toEqual([second.run.id]);
    // O achado nasceu na execução apagada: continua existindo, sem a referência.
    const [kept] = await db.select().from(findings).where(eq(findings.id, first.findings[0].id));
    expect(kept).toMatchObject({ assessmentId: null, lastAssessmentId: second.run.id });
  });

  it("apaga achados encerrados há mais tempo que o prazo e preserva os abertos", async () => {
    const { org, scope, repo } = await newOrg();
    const asset = await repo.createAsset({ name: "API", url: "https://api.example.com", kind: "API", owner: "TI", authorizationId: scope.id });
    const { findings: [closed, open] } = await repo.recordAssessment(asset.id, "M", daysAgo(500), [finding("Antigo"), finding("Aberto")], daysAgo(500));
    await db.update(findings).set({ status: "fixed", statusChangedAt: daysAgo(400) }).where(eq(findings.id, closed.id));
    const result = await applyOrganizationRetention(db, org.id, { auditRetentionDays: 1825, assessmentRetentionDays: null, closedFindingRetentionDays: 365, scopeContactRetentionDays: 365 }, now);
    expect(result.findings).toBe(1);
    const left = await db.select({ id: findings.id }).from(findings).where(eq(findings.organizationId, org.id));
    expect(left.map(f => f.id)).toEqual([open.id]);
  });

  it("apaga o contato de emergência de escopos encerrados há mais tempo que o prazo", async () => {
    const { org, scope } = await newOrg();
    const [revoked] = await db.insert(authorizations).values({ organizationId: org.id, reference: "AUT-R", hostnames: ["x.example.com"], status: "revoked", revokedAt: daysAgo(200), validUntil: new Date(now.getTime() + 100 * DAY), emergencyContact: "ana@cliente.com.br" }).returning();
    const [expired] = await db.insert(authorizations).values({ organizationId: org.id, reference: "AUT-V", hostnames: ["y.example.com"], status: "approved", validUntil: daysAgo(20), emergencyContact: "bia@cliente.com.br" }).returning();
    await applyOrganizationRetention(db, org.id, { auditRetentionDays: 1825, assessmentRetentionDays: null, closedFindingRetentionDays: null, scopeContactRetentionDays: 180 }, now);
    const rows = Object.fromEntries((await db.select().from(authorizations).where(eq(authorizations.organizationId, org.id))).map(r => [r.id, r.emergencyContact]));
    expect(rows).toEqual({ [scope.id]: "plantao@cliente.com.br", [revoked.id]: null, [expired.id]: "bia@cliente.com.br" });
  });

  it("applyRetention usa os prazos de cada organização e limpa sessões vencidas", async () => {
    const a = await newOrg(), b = await newOrg();
    await db.update(organizations).set({ auditRetentionDays: 180 }).where(eq(organizations.id, a.org.id));
    await db.insert(auditLog).values([a, b].map(({ org }) => ({ organizationId: org.id, action: "auth.logout", targetType: "user", createdAt: daysAgo(200) })));
    const person = await member(a.org.id);
    await createSession(db, { userId: person.id, organizationId: a.org.id }, daysAgo(60));
    await applyRetention(db, now);
    const count = async (orgId: string) => (await db.select().from(auditLog).where(eq(auditLog.organizationId, orgId))).filter(r => r.action === "auth.logout").length;
    expect(await count(a.org.id)).toBe(0);
    expect(await count(b.org.id)).toBe(1);
    expect(await db.select().from(sessions).where(eq(sessions.userId, person.id))).toEqual([]);
  });
});

describe("direitos do titular", () => {
  it("exporta os dados pessoais sem hashes nem segredos", async () => {
    const { org, repo } = await newOrg();
    const person = await member(org.id);
    await createSession(db, { userId: person.id, organizationId: org.id, ip: "198.51.100.7", userAgent: "Firefox" });
    await createApiToken(db, { organizationId: org.id, userId: person.id, userRole: "viewer", name: "CI", role: "viewer", days: 30 });
    await tenantRepository(db, org.id, person.id).audit("auth.login_succeeded", "user", person.id, { ip: "198.51.100.7" });
    await repo.audit("user.created", "user", person.id, { email: person.email });
    const data = await exportPersonalData(db, person.id, org.id);
    expect(data?.profile).toMatchObject({ email: person.email, hasPassword: true });
    expect(data?.sessions[0]).toMatchObject({ ip: "198.51.100.7", userAgent: "Firefox" });
    expect(data?.apiTokens[0]).toMatchObject({ name: "CI", role: "viewer" });
    expect(data?.activity.map(a => a.action).sort()).toEqual(["auth.login_succeeded", "user.created"]);
    const text = JSON.stringify(data);
    expect(text).not.toMatch(/password_?hash|argon|tokenHash|totp/i);
  });

  it("anonimiza: apaga identificação, acessos e IPs, mas mantém o histórico de ações", async () => {
    const { org, repo } = await newOrg();
    await member(org.id, "owner");
    const person = await member(org.id, "admin");
    await createSession(db, { userId: person.id, organizationId: org.id, ip: "198.51.100.7" });
    await createApiToken(db, { organizationId: org.id, userId: person.id, userRole: "admin", name: "CI", role: "analyst", days: 30 });
    await db.insert(ssoIdentities).values({ userId: person.id, organizationId: org.id, issuer: "https://idp.example.com", subject: "abc" });
    await db.insert(notifications).values({ organizationId: org.id, userId: person.id, kind: "x", title: "Aviso" });
    await tenantRepository(db, org.id, person.id).audit("scope.approved", "authorization", "s1", { reference: "AUT-1", ip: "198.51.100.7" });
    await repo.audit("auth.sso_rejected", "organization", org.id, { email: person.email.toUpperCase(), reason: "domain" });

    await anonymizeUser(db, org.id, person.id);

    const [row] = await db.select().from(users).where(eq(users.id, person.id));
    expect(row).toMatchObject({ email: anonymizedEmail(person.id), name: ANONYMIZED_NAME, passwordHash: null, totpSecret: null, disabled: true, emailNotifications: false });
    for (const table of [sessions, apiTokens, ssoIdentities, notifications]) expect(await db.select().from(table).where(eq(table.userId, person.id))).toEqual([]);
    const audit = await db.select().from(auditLog).where(eq(auditLog.organizationId, org.id));
    expect(audit.find(a => a.action === "scope.approved")).toMatchObject({ actorUserId: person.id, metadata: { reference: "AUT-1" } });
    expect(JSON.stringify(audit)).not.toContain("198.51.100.7");
    expect(JSON.stringify(audit).toLowerCase()).not.toContain(person.email.toLowerCase());
    // A membresia continua: as ações seguem atribuídas a "Pessoa removida".
    expect(await db.select().from(memberships).where(eq(memberships.userId, person.id))).toHaveLength(1);
  });

  it("recusa anonimizar o último Owner ativo ou quem participa de outra organização", async () => {
    const a = await newOrg(), b = await newOrg();
    const owner = await member(a.org.id, "owner");
    await expect(anonymizeUser(db, a.org.id, owner.id)).rejects.toThrow("ao menos um Owner");
    const shared = await member(a.org.id);
    await db.insert(memberships).values({ organizationId: b.org.id, userId: shared.id, role: "viewer" });
    await expect(anonymizeUser(db, a.org.id, shared.id)).rejects.toThrow("outra organização");
    await expect(anonymizeUser(db, b.org.id, owner.id)).rejects.toThrow("não encontrado");
  });

  it("exporta a organização sem segredos de webhook, SSO nem hash de token", async () => {
    const { org } = await newOrg();
    const owner = await member(org.id, "owner");
    await createApiToken(db, { organizationId: org.id, userId: owner.id, userRole: "owner", name: "CI", role: "viewer", days: 7 });
    await db.insert(webhooks).values({ organizationId: org.id, name: "SIEM", url: "https://siem.example.com/hook", secret: "cifrado-webhook", events: ["scope.approved"] });
    await db.insert(ssoConnections).values({ organizationId: org.id, issuer: "https://idp.example.com", clientId: "sentinela", clientSecret: "cifrado-sso", allowedDomains: ["example.com"] });
    const data = await exportOrganization(db, org.id);
    expect(data?.members.map(m => m.email)).toEqual([owner.email]);
    expect(data?.scopes).toHaveLength(1);
    expect(data?.webhooks[0]).toMatchObject({ name: "SIEM", url: "https://siem.example.com/hook" });
    expect(data?.sso).toMatchObject({ issuer: "https://idp.example.com", clientId: "sentinela" });
    const text = JSON.stringify(data);
    for (const secret of ["cifrado-webhook", "cifrado-sso", "tokenHash", "passwordHash", "totpSecret"]) expect(text).not.toContain(secret);
  });
});
