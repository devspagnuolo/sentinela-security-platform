import { eq, sql } from "drizzle-orm";
import type { Database } from "@/db/client";
import { tenantRepository } from "@/db/repository";
import { users } from "@/db/schema";
import { findUserByEmail, primaryMembership } from "@/db/users";
import { burnVerification, verifyPassword } from "./password";
import { createSession } from "./session";

export const MAX_FAILED_LOGINS = 5;
export const LOCKOUT_MS = 15 * 60 * 1000;
export const INVALID_CREDENTIALS = "E-mail ou senha inválidos.";

type Meta = { ip?: string | null; userAgent?: string | null };
export type LoginResult = { ok: true; token: string; expiresAt: Date } | { ok: false; error: string };

/**
 * Autentica por e-mail e senha. A resposta de erro é sempre a mesma (sem revelar
 * se o e-mail existe ou se a conta está bloqueada); após MAX_FAILED_LOGINS falhas
 * seguidas a conta fica bloqueada por LOCKOUT_MS.
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

  await db.update(users).set({ failedLoginCount: 0, lockedUntil: null, lastLoginAt: now }).where(eq(users.id, user.id));
  const session = await createSession(db, { userId: user.id, organizationId: membership.organizationId, ...meta }, now);
  await audit.audit("auth.login_succeeded", "user", user.id, { ip: meta.ip ?? null });
  return { ok: true, ...session };
}
