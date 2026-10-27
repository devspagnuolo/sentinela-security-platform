import { eq, sql } from "drizzle-orm";
import type { Database } from "@/db/client";
import { tenantRepository } from "@/db/repository";
import { ssoConnections, users } from "@/db/schema";
import { findUserByEmail, primaryMembership } from "@/db/users";
import { burnVerification, verifyPassword } from "./password";
import { LOCKOUT_MS, MAX_FAILED_LOGINS } from "./limits";
import { createMfaChallenge } from "./mfa";
import { createSession } from "./session";

export { LOCKOUT_MS, MAX_FAILED_LOGINS } from "./limits";
export const INVALID_CREDENTIALS = "E-mail ou senha inválidos.";
export const SSO_REQUIRED = "Sua organização exige o login via SSO. Use o botão \"Entrar com SSO\".";

type Meta = { ip?: string | null; userAgent?: string | null };
export type LoginResult = { ok: true; token: string; expiresAt: Date } | { ok: "mfa"; challenge: string } | { ok: false; error: string };

/**
 * Autentica por e-mail e senha. A resposta de erro é sempre a mesma (sem revelar
 * se o e-mail existe ou se a conta está bloqueada); após MAX_FAILED_LOGINS falhas
 * seguidas a conta fica bloqueada por LOCKOUT_MS. Usuários com MFA recebem um
 * desafio em vez da sessão (segunda etapa em completeMfaLogin).
 */
export async function login(db: Database, email: string, password: string, meta: Meta = {}, now = new Date()): Promise<LoginResult> {
  const user = await findUserByEmail(db, email);
  if (!user?.passwordHash) { await burnVerification(password); return { ok: false, error: INVALID_CREDENTIALS }; }
  const membership = await primaryMembership(db, user.id);
  const audit = membership && tenantRepository(db, membership.organizationId, user.id);
  const locked = user.lockedUntil && user.lockedUntil > now;
  const valid = await verifyPassword(password, user.passwordHash);

  if (locked || user.disabled || !membership || !valid) {
    if (!locked && !valid) {
      const failures = user.failedLoginCount + 1;
      const lock = failures >= MAX_FAILED_LOGINS;
      await db.update(users).set(lock ? { failedLoginCount: 0, lockedUntil: new Date(now.getTime() + LOCKOUT_MS) } : { failedLoginCount: sql`${users.failedLoginCount} + 1` }).where(eq(users.id, user.id));
      await audit?.audit(lock ? "auth.account_locked" : "auth.login_failed", "user", user.id, { ip: meta.ip ?? null, failures });
    } else {
      await audit?.audit("auth.login_rejected", "user", user.id, { ip: meta.ip ?? null, reason: locked ? "locked" : user.disabled ? "disabled" : "no_membership" });
    }
    return { ok: false, error: INVALID_CREDENTIALS };
  }

  // SSO obrigatório: só Owners mantêm o login por senha (acesso de emergência se o provedor cair).
  if (membership.role !== "owner") {
    const [sso] = await db.select({ enforced: ssoConnections.enforced, enabled: ssoConnections.enabled }).from(ssoConnections).where(eq(ssoConnections.organizationId, membership.organizationId));
    if (sso?.enabled && sso.enforced) {
      await audit.audit("auth.login_rejected", "user", user.id, { ip: meta.ip ?? null, reason: "sso_enforced" });
      return { ok: false, error: SSO_REQUIRED };
    }
  }

  if (user.totpEnabledAt) {
    await audit.audit("auth.password_verified", "user", user.id, { ip: meta.ip ?? null });
    return { ok: "mfa", challenge: await createMfaChallenge(db, user.id, membership.organizationId, now) };
  }
  await db.update(users).set({ failedLoginCount: 0, lockedUntil: null, lastLoginAt: now }).where(eq(users.id, user.id));
  const session = await createSession(db, { userId: user.id, organizationId: membership.organizationId, ...meta }, now);
  await audit.audit("auth.login_succeeded", "user", user.id, { ip: meta.ip ?? null });
  return { ok: true, ...session };
}
