import { createHash, randomBytes } from "node:crypto";
import { and, eq, gt, lt, ne } from "drizzle-orm";
import type { Database } from "@/db/client";
import { memberships, organizations, sessions, users } from "@/db/schema";
import type { Role } from "./rbac";

export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
export const SESSION_IDLE_MS = 2 * 60 * 60 * 1000;
const TOUCH_INTERVAL_MS = 5 * 60 * 1000;

export type SessionUser = { id: string; email: string; name: string };
/** "token": requisição autenticada por token de API (src/lib/auth/tokens.ts), sem cookie. */
export type AuthMethod = "password" | "mfa" | "sso" | "token";
export type ActiveSession = {
  id: string; organizationId: string; role: Role; user: SessionUser; expiresAt: Date;
  /** Usuário tem MFA ativo. */
  mfaEnabled: boolean;
  /** A organização exige MFA e o usuário ainda não cadastrou: só pode acessar a própria conta. Login via SSO cumpre a exigência. */
  mfaEnrollmentRequired: boolean;
  authMethod: AuthMethod;
};

const hashToken = (token: string) => createHash("sha256").update(token).digest("hex");

export async function createSession(db: Database, input: { userId: string; organizationId: string; authMethod?: AuthMethod; ip?: string | null; userAgent?: string | null }, now = new Date()) {
  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(now.getTime() + SESSION_TTL_MS);
  await db.insert(sessions).values({ id: hashToken(token), userId: input.userId, organizationId: input.organizationId, authMethod: input.authMethod ?? "password", createdAt: now, lastSeenAt: now, expiresAt, ip: input.ip?.slice(0, 64) ?? null, userAgent: input.userAgent?.slice(0, 256) ?? null });
  return { token, expiresAt };
}

/** Valida o token do cookie: sessão vigente, não ociosa, usuário ativo e ainda membro da organização. */
export async function validateSession(db: Database, token: string | undefined, now = new Date()): Promise<ActiveSession | null> {
  if (!token || token.length > 128) return null;
  const id = hashToken(token);
  const [row] = await db
    .select({ session: sessions, user: users, role: memberships.role, requireMfa: organizations.requireMfa })
    .from(sessions)
    .innerJoin(users, eq(users.id, sessions.userId))
    .innerJoin(memberships, and(eq(memberships.userId, sessions.userId), eq(memberships.organizationId, sessions.organizationId)))
    .innerJoin(organizations, eq(organizations.id, sessions.organizationId))
    .where(and(eq(sessions.id, id), gt(sessions.expiresAt, now)));
  if (!row || row.user.disabled || now.getTime() - row.session.lastSeenAt.getTime() > SESSION_IDLE_MS) {
    if (row) await db.delete(sessions).where(eq(sessions.id, id));
    return null;
  }
  if (now.getTime() - row.session.lastSeenAt.getTime() > TOUCH_INTERVAL_MS) await db.update(sessions).set({ lastSeenAt: now }).where(eq(sessions.id, id));
  return { id, organizationId: row.session.organizationId, role: row.role, user: { id: row.user.id, email: row.user.email, name: row.user.name }, expiresAt: row.session.expiresAt, mfaEnabled: Boolean(row.user.totpEnabledAt), mfaEnrollmentRequired: row.requireMfa && !row.user.totpEnabledAt && row.session.authMethod !== "sso", authMethod: row.session.authMethod as AuthMethod };
}

export async function revokeSession(db: Database, token: string | undefined) {
  if (token) await db.delete(sessions).where(eq(sessions.id, hashToken(token)));
}

export async function revokeUserSessions(db: Database, userId: string, exceptSessionId?: string) {
  await db.delete(sessions).where(exceptSessionId ? and(eq(sessions.userId, userId), ne(sessions.id, exceptSessionId)) : eq(sessions.userId, userId));
}

export async function purgeExpiredSessions(db: Database, now = new Date()) {
  await db.delete(sessions).where(lt(sessions.expiresAt, now));
}
