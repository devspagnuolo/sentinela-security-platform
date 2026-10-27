import { eq } from "drizzle-orm";
import type { Database } from "./client";
import { hashPassword } from "@/lib/auth/password";
import { findingFingerprint } from "@/lib/scope";
import { assessmentFindings, assessments, assets, authorizations, clients, findings, memberships, organizations, users } from "./schema";

export const DEFAULT_ORG_SLUG = "default";
export const DEMO_OWNER_EMAIL = "admin@sentinela.local";

/**
 * Cria a organização padrão com dados demonstrativos, se ainda não existir. Idempotente.
 * Com ownerPassword, cria também o Owner demonstrativo admin@sentinela.local.
 */
export async function seedDemo(db: Database, options: { ownerPassword?: string } = {}) {
  const existing = await db.select({ id: organizations.id }).from(organizations).where(eq(organizations.slug, DEFAULT_ORG_SLUG));
  if (existing.length) return existing[0].id;
  const passwordHash = options.ownerPassword ? await hashPassword(options.ownerPassword) : undefined;
  return db.transaction(async tx => {
    const [org] = await tx.insert(organizations).values({ slug: DEFAULT_ORG_SLUG, name: "Minha consultoria" }).returning();
    if (passwordHash) {
      const [owner] = await tx.insert(users).values({ email: DEMO_OWNER_EMAIL, name: "Administrador demo", passwordHash, passwordChangedAt: new Date() }).returning();
      await tx.insert(memberships).values({ organizationId: org.id, userId: owner.id, role: "owner" });
    }
    const ownerId = passwordHash ? (await tx.select({ id: users.id }).from(users).where(eq(users.email, DEMO_OWNER_EMAIL)))[0]?.id ?? null : null;
    const now = new Date();
    const [demoClient] = await tx.insert(clients).values({ organizationId: org.id, name: "Cliente demonstrativo" }).returning();
    const [scope] = await tx.insert(authorizations).values({
      organizationId: org.id, clientId: demoClient.id, reference: "DEMO-2026-001", hostnames: ["portal.example.com", "api.example.com"], status: "approved",
      validFrom: now, validUntil: new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000), emergencyContact: "seguranca@example.com", exclusions: "Dados demonstrativos.",
      createdBy: ownerId, approvedBy: ownerId, approvedAt: now
    }).returning();
    const [portal, api] = await tx.insert(assets).values([
      { organizationId: org.id, authorizationId: scope.id, name: "Portal institucional", url: "https://portal.example.com", kind: "Web application", owner: "Equipe Digital", authorizationRef: scope.reference },
      { organizationId: org.id, authorizationId: scope.id, name: "API de serviços", url: "https://api.example.com", kind: "API", owner: "Plataforma", authorizationRef: scope.reference }
    ]).returning();
    const [runPortal, runApi] = await tx.insert(assessments).values([
      { organizationId: org.id, assetId: portal.id, status: "completed", method: "SENTINELA-HTTP-001", finishedAt: now },
      { organizationId: org.id, assetId: api.id, status: "completed", method: "SENTINELA-HTTP-001", finishedAt: now }
    ]).returning();
    const demo = [
      { assetId: portal.id, assessmentId: runPortal.id, title: "Política de segurança de conteúdo ausente", severity: "medium" as const, category: "HTTP Headers", description: "A resposta observada não incluiu Content-Security-Policy.", evidence: "Header ausente na resposta da raiz", recommendation: "Defina uma política CSP adequada ao inventário de recursos e monitore violações antes de aplicar bloqueio estrito.", references: ["OWASP Secure Headers"] },
      { assetId: api.id, assessmentId: runApi.id, title: "HSTS ausente", severity: "low" as const, category: "TLS / HTTP", description: "A resposta HTTPS observada não incluiu Strict-Transport-Security.", evidence: "Header ausente na resposta da raiz", recommendation: "Após confirmar suporte HTTPS em todo o domínio, habilite HSTS com max-age gradual.", references: ["OWASP Secure Headers"] },
      { assetId: portal.id, assessmentId: runPortal.id, title: "Cookie sem atributo SameSite explícito", severity: "low" as const, category: "Cookies", description: "Ao menos um cookie observado não declarou SameSite.", evidence: "Atributo SameSite ausente; valores de cookie foram omitidos", recommendation: "Configure SameSite=Lax ou Strict conforme o fluxo, além de Secure e HttpOnly quando aplicável.", references: ["OWASP Session Management Cheat Sheet"] }
    ];
    const rows = await tx.insert(findings).values(demo.map(f => ({ ...f, organizationId: org.id, fingerprint: findingFingerprint(f), lastAssessmentId: f.assessmentId }))).returning();
    await tx.insert(assessmentFindings).values(rows.map(r => ({ organizationId: org.id, assessmentId: r.assessmentId!, findingId: r.id, evidence: r.evidence })));
    return org.id;
  });
}
