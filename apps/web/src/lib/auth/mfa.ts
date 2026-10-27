import { createHash, randomBytes } from "node:crypto";
import { and, eq, isNull, sql } from "drizzle-orm";
import QRCode from "qrcode";
import type { Database } from "@/db/client";
import { tenantRepository } from "@/db/repository";
import { mfaChallenges, recoveryCodes, users } from "@/db/schema";
import { decrypt, encrypt, keyedHash } from "@/lib/crypto";
import { LOCKOUT_MS, MAX_FAILED_LOGINS } from "./limits";
import { createSession } from "./session";
import { generateRecoveryCodes, generateTotpSecret, normalizeRecoveryCode, otpauthUri, verifyTotp } from "./totp";

export const MFA_CHALLENGE_TTL_MS = 5 * 60 * 1000;
export const MFA_CHALLENGE_MAX_ATTEMPTS = 5;
export const INVALID_MFA_CODE = "Código inválido ou expirado.";

const hashToken = (token: string) => createHash("sha256").update(token).digest("hex");
type Meta = { ip?: string | null; userAgent?: string | null };

export async function createMfaChallenge(db: Database, userId: string, organizationId: string, now = new Date()) {
  const token = randomBytes(32).toString("base64url");
  await db.insert(mfaChallenges).values({ id: hashToken(token), userId, organizationId, expiresAt: new Date(now.getTime() + MFA_CHALLENGE_TTL_MS), createdAt: now });
  return token;
}

async function consumeRecoveryCode(db: Database, userId: string, code: string, now: Date) {
  const normalized = normalizeRecoveryCode(code);
  if (normalized.length !== 10) return false;
  const used = await db.update(recoveryCodes).set({ usedAt: now }).where(and(eq(recoveryCodes.userId, userId), eq(recoveryCodes.codeHash, keyedHash(normalized)), isNull(recoveryCodes.usedAt))).returning({ id: recoveryCodes.id });
  return used.length > 0;
}

/** Confere um código TOTP (com proteção contra reuso) ou de recuperação do usuário. */
export async function checkSecondFactor(db: Database, user: typeof users.$inferSelect, code: string, now = new Date()): Promise<"totp" | "recovery" | null> {
  if (!user.totpSecret || !user.totpEnabledAt) return null;
  const step = verifyTotp(decrypt(user.totpSecret), code, user.totpLastStep, now.getTime());
  if (step !== null) {
    // Atualização condicional: duas requisições simultâneas com o mesmo código não passam ambas.
    const updated = await db.update(users).set({ totpLastStep: step }).where(and(eq(users.id, user.id), sql`coalesce(${users.totpLastStep}, -1) < ${step}`)).returning({ id: users.id });
    return updated.length ? "totp" : null;
  }
  return (await consumeRecoveryCode(db, user.id, code, now)) ? "recovery" : null;
}

export type MfaResult = { ok: true; token: string; expiresAt: Date; method: "totp" | "recovery" } | { ok: false; error: string };

/** Segunda etapa do login: troca desafio + código por uma sessão. */
export async function completeMfaLogin(db: Database, challengeToken: string, code: string, meta: Meta = {}, now = new Date()): Promise<MfaResult> {
  const id = hashToken(challengeToken);
  const [challenge] = await db.select().from(mfaChallenges).where(eq(mfaChallenges.id, id));
  if (!challenge || challenge.expiresAt <= now || challenge.attempts >= MFA_CHALLENGE_MAX_ATTEMPTS) {
    if (challenge) await db.delete(mfaChallenges).where(eq(mfaChallenges.id, id));
    return { ok: false, error: INVALID_MFA_CODE };
  }
  const [user] = await db.select().from(users).where(eq(users.id, challenge.userId));
  const audit = tenantRepository(db, challenge.organizationId, challenge.userId);
  if (!user || user.disabled || (user.lockedUntil && user.lockedUntil > now)) {
    await db.delete(mfaChallenges).where(eq(mfaChallenges.id, id));
    return { ok: false, error: INVALID_MFA_CODE };
  }
  const method = await checkSecondFactor(db, user, code, now);
  if (!method) {
    await db.update(mfaChallenges).set({ attempts: sql`${mfaChallenges.attempts} + 1` }).where(eq(mfaChallenges.id, id));
    const failures = user.failedLoginCount + 1;
    const lock = failures >= MAX_FAILED_LOGINS;
    await db.update(users).set(lock ? { failedLoginCount: 0, lockedUntil: new Date(now.getTime() + LOCKOUT_MS) } : { failedLoginCount: sql`${users.failedLoginCount} + 1` }).where(eq(users.id, user.id));
    await audit.audit(lock ? "auth.account_locked" : "auth.mfa_failed", "user", user.id, { ip: meta.ip ?? null, failures });
    return { ok: false, error: INVALID_MFA_CODE };
  }
  await db.delete(mfaChallenges).where(eq(mfaChallenges.id, id));
  await db.update(users).set({ failedLoginCount: 0, lockedUntil: null, lastLoginAt: now }).where(eq(users.id, user.id));
  const session = await createSession(db, { userId: user.id, organizationId: challenge.organizationId, authMethod: "mfa", ...meta }, now);
  await audit.audit("auth.login_succeeded", "user", user.id, { ip: meta.ip ?? null, mfa: method });
  return { ok: true, method, ...session };
}

/** Inicia (ou reinicia) o cadastro: grava um segredo pendente e devolve URI e QR code. */
export async function beginTotpSetup(db: Database, userId: string, email: string) {
  const secret = generateTotpSecret();
  await db.update(users).set({ totpPendingSecret: encrypt(secret) }).where(eq(users.id, userId));
  const uri = otpauthUri(secret, email);
  return { secret, uri, qrSvg: await QRCode.toString(uri, { type: "svg", margin: 1, errorCorrectionLevel: "M" }) };
}

/** Confirma o segredo pendente com um código válido, ativa o MFA e gera novos códigos de recuperação. */
export async function confirmTotpSetup(db: Database, userId: string, code: string, now = new Date()): Promise<string[] | null> {
  const [user] = await db.select().from(users).where(eq(users.id, userId));
  if (!user?.totpPendingSecret) return null;
  const secret = decrypt(user.totpPendingSecret);
  const step = verifyTotp(secret, code, null, now.getTime());
  if (step === null) return null;
  await db.update(users).set({ totpSecret: user.totpPendingSecret, totpPendingSecret: null, totpEnabledAt: now, totpLastStep: step }).where(eq(users.id, userId));
  return replaceRecoveryCodes(db, userId);
}

export async function replaceRecoveryCodes(db: Database, userId: string): Promise<string[]> {
  const codes = generateRecoveryCodes();
  await db.transaction(async tx => {
    await tx.delete(recoveryCodes).where(eq(recoveryCodes.userId, userId));
    await tx.insert(recoveryCodes).values(codes.map(code => ({ userId, codeHash: keyedHash(normalizeRecoveryCode(code)) })));
  });
  return codes;
}

export async function remainingRecoveryCodes(db: Database, userId: string) {
  const rows = await db.select({ id: recoveryCodes.id }).from(recoveryCodes).where(and(eq(recoveryCodes.userId, userId), isNull(recoveryCodes.usedAt)));
  return rows.length;
}

/** Remove o MFA do usuário (desativação própria ou reset administrativo). */
export async function disableMfa(db: Database, userId: string) {
  await db.transaction(async tx => {
    await tx.update(users).set({ totpSecret: null, totpPendingSecret: null, totpEnabledAt: null, totpLastStep: null }).where(eq(users.id, userId));
    await tx.delete(recoveryCodes).where(eq(recoveryCodes.userId, userId));
    await tx.delete(mfaChallenges).where(eq(mfaChallenges.userId, userId));
  });
}
