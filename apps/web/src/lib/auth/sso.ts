import { createHash, timingSafeEqual } from "node:crypto";
import { and, eq, lt } from "drizzle-orm";
import * as oidc from "openid-client";
import type { Database } from "@/db/client";
import { tenantRepository } from "@/db/repository";
import { memberships, ssoConnections, ssoIdentities, ssoRequests, users } from "@/db/schema";
import { findUserByEmail } from "@/db/users";
import { decrypt, encrypt } from "@/lib/crypto";
import type { Role } from "./rbac";
import { createSession } from "./session";

export const SSO_REQUEST_TTL_MS = 10 * 60 * 1000;
const DISCOVERY_TTL_MS = 60 * 60 * 1000;

export type SsoConnection = typeof ssoConnections.$inferSelect;
export type SsoErrorCode = "sso_unavailable" | "sso_expired" | "sso_failed" | "sso_not_provisioned";
type Meta = { ip?: string | null; userAgent?: string | null };

const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");
const domainOf = (email: string) => email.trim().toLowerCase().split("@").pop() ?? "";

/** HTTP sem TLS só para emissores locais fora de produção (testes e Keycloak de desenvolvimento). */
export function isInsecureIssuerAllowed(issuer: string) {
  const url = new URL(issuer);
  return url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) && process.env.NODE_ENV !== "production";
}

/** Origem pública da aplicação, usada no redirect_uri registrado no provedor. */
export function publicOrigin(request: Request) {
  const configured = process.env.SENTINELA_PUBLIC_ORIGIN?.split(",")[0]?.trim();
  if (configured) return configured.replace(/\/$/, "");
  const url = new URL(request.url);
  const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host");
  return host ? `${request.headers.get("x-forwarded-proto") ?? url.protocol.replace(":", "")}://${host}` : url.origin;
}
export const redirectUriFor = (origin: string) => `${origin}/api/auth/sso/callback`;

const discoveryCache = new Map<string, { config: oidc.Configuration; at: number }>();

/** Descobre os endpoints do emissor (.well-known/openid-configuration), com cache de 1 h. */
export async function oidcConfiguration(input: { issuer: string; clientId: string; clientSecret: string }, now = Date.now()) {
  const key = sha256(`${input.issuer}\n${input.clientId}\n${input.clientSecret}`);
  const cached = discoveryCache.get(key);
  if (cached && now - cached.at < DISCOVERY_TTL_MS) return cached.config;
  const config = await oidc.discovery(new URL(input.issuer), input.clientId, input.clientSecret, undefined, {
    execute: isInsecureIssuerAllowed(input.issuer) ? [oidc.allowInsecureRequests] : [],
    timeout: 10
  });
  discoveryCache.set(key, { config, at: now });
  return config;
}

const configFor = (conn: SsoConnection) => oidcConfiguration({ issuer: conn.issuer, clientId: conn.clientId, clientSecret: decrypt(conn.clientSecret) });

export async function getSsoConnection(db: Database, organizationId: string) {
  const [conn] = await db.select().from(ssoConnections).where(eq(ssoConnections.organizationId, organizationId));
  return conn;
}

/** Conexão ativa cujo domínio permitido corresponde ao e-mail informado no login. */
export async function findSsoConnectionForEmail(db: Database, email: string) {
  const domain = domainOf(email);
  if (!domain) return undefined;
  const enabled = await db.select().from(ssoConnections).where(eq(ssoConnections.enabled, true));
  return enabled.find(conn => conn.allowedDomains.includes(domain));
}

/** Gera state, nonce e PKCE; grava o pedido e devolve a URL de autorização do provedor. */
export async function startSso(db: Database, conn: SsoConnection, redirectUri: string, loginHint?: string, now = new Date()) {
  const config = await configFor(conn);
  const state = oidc.randomState(), nonce = oidc.randomNonce(), codeVerifier = oidc.randomPKCECodeVerifier();
  await db.delete(ssoRequests).where(lt(ssoRequests.expiresAt, now));
  await db.insert(ssoRequests).values({ id: sha256(state), organizationId: conn.organizationId, nonce, codeVerifier: encrypt(codeVerifier), expiresAt: new Date(now.getTime() + SSO_REQUEST_TTL_MS), createdAt: now });
  const url = oidc.buildAuthorizationUrl(config, {
    redirect_uri: redirectUri, scope: "openid email profile", state, nonce,
    code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier), code_challenge_method: "S256",
    ...(loginHint && { login_hint: loginHint })
  });
  return { state, url };
}

function sameState(a: string | undefined, b: string) {
  if (!a || a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

type Claims = { sub: string; email?: string; email_verified?: boolean; name?: string; preferred_username?: string };

/**
 * Conclui o login: confere o state com o cookie do navegador (impede login CSRF),
 * troca o código com PKCE, valida o ID token (assinatura, iss, aud, exp, nonce)
 * e associa a identidade a um usuário da organização.
 */
export async function completeSso(db: Database, input: { state: string | null; cookieState: string | undefined; callbackUrl: URL; meta?: Meta }, now = new Date()): Promise<{ ok: true; token: string; expiresAt: Date } | { ok: false; error: SsoErrorCode }> {
  if (!input.state || !sameState(input.cookieState, input.state)) return { ok: false, error: "sso_expired" };
  const [pending] = await db.delete(ssoRequests).where(eq(ssoRequests.id, sha256(input.state))).returning();
  if (!pending || pending.expiresAt <= now) return { ok: false, error: "sso_expired" };
  const conn = await getSsoConnection(db, pending.organizationId);
  if (!conn?.enabled) return { ok: false, error: "sso_unavailable" };
  const audit = tenantRepository(db, conn.organizationId);

  let claims: Claims;
  try {
    const tokens = await oidc.authorizationCodeGrant(await configFor(conn), input.callbackUrl, {
      pkceCodeVerifier: decrypt(pending.codeVerifier), expectedState: input.state, expectedNonce: pending.nonce, idTokenExpected: true
    });
    claims = tokens.claims() as unknown as Claims;
  } catch (error) {
    await audit.audit("auth.sso_failed", "organization", conn.organizationId, { ip: input.meta?.ip ?? null, reason: error instanceof Error ? error.message.slice(0, 200) : "unknown" });
    return { ok: false, error: "sso_failed" };
  }

  const resolved = await resolveUser(db, conn, claims);
  if (!resolved.ok) {
    await audit.audit("auth.sso_rejected", "organization", conn.organizationId, { ip: input.meta?.ip ?? null, reason: resolved.reason, email: claims.email ?? null });
    return { ok: false, error: "sso_not_provisioned" };
  }
  const { userId, provisioned } = resolved;
  const userAudit = tenantRepository(db, conn.organizationId, userId);
  if (provisioned) await userAudit.audit("user.provisioned_sso", "user", userId, { role: conn.jitRole });
  await db.update(users).set({ lastLoginAt: now }).where(eq(users.id, userId));
  const session = await createSession(db, { userId, organizationId: conn.organizationId, authMethod: "sso", ...input.meta }, now);
  await userAudit.audit("auth.login_succeeded", "user", userId, { ip: input.meta?.ip ?? null, method: "sso" });
  return { ok: true, ...session };
}

type Resolution = { ok: true; userId: string; provisioned: boolean } | { ok: false; reason: string };

async function resolveUser(db: Database, conn: SsoConnection, claims: Claims): Promise<Resolution> {
  const isMember = async (userId: string) => (await db.select({ id: memberships.id }).from(memberships).where(and(eq(memberships.userId, userId), eq(memberships.organizationId, conn.organizationId)))).length > 0;
  const active = async (userId: string): Promise<Resolution> => {
    const [user] = await db.select({ disabled: users.disabled }).from(users).where(eq(users.id, userId));
    if (!user || user.disabled) return { ok: false, reason: "disabled" };
    return await isMember(userId) ? { ok: true, userId, provisioned: false } : { ok: false, reason: "no_membership" };
  };

  const [identity] = await db.select().from(ssoIdentities).where(and(eq(ssoIdentities.issuer, conn.issuer), eq(ssoIdentities.subject, claims.sub)));
  if (identity) return identity.organizationId === conn.organizationId ? active(identity.userId) : { ok: false, reason: "other_organization" };

  // Primeiro login dessa identidade: só e-mails de domínios permitidos e não marcados como não verificados.
  const email = claims.email?.trim().toLowerCase();
  if (!email || claims.email_verified === false) return { ok: false, reason: "email_unverified" };
  if (!conn.allowedDomains.includes(domainOf(email))) return { ok: false, reason: "domain_not_allowed" };

  const existing = await findUserByEmail(db, email);
  if (existing) {
    const result = await active(existing.id);
    if (result.ok) await db.insert(ssoIdentities).values({ userId: existing.id, organizationId: conn.organizationId, issuer: conn.issuer, subject: claims.sub });
    return result;
  }
  if (!conn.jitRole) return { ok: false, reason: "not_provisioned" };
  const role: Role = conn.jitRole;
  const name = (claims.name ?? claims.preferred_username ?? email.split("@")[0]).trim().slice(0, 100) || email;
  const userId = await db.transaction(async tx => {
    const [user] = await tx.insert(users).values({ email, name }).returning({ id: users.id });
    await tx.insert(memberships).values({ organizationId: conn.organizationId, userId: user.id, role });
    await tx.insert(ssoIdentities).values({ userId: user.id, organizationId: conn.organizationId, issuer: conn.issuer, subject: claims.sub });
    return user.id;
  });
  return { ok: true, userId, provisioned: true };
}

/** Visão segura da configuração (sem o client secret). */
export const ssoView = (conn: SsoConnection | undefined, redirectUri: string) => conn
  ? { configured: true, issuer: conn.issuer, clientId: conn.clientId, allowedDomains: conn.allowedDomains, enabled: conn.enabled, enforced: conn.enforced, jitRole: conn.jitRole, redirectUri }
  : { configured: false, redirectUri };
