import { createHash, randomBytes } from "node:crypto";
import { and, count, desc, eq, gt, isNull } from "drizzle-orm";
import type { Database } from "@/db/client";
import { apiTokens, memberships, organizations, users } from "@/db/schema";
import { lowerRole, rankOf, type Role } from "./rbac";
import type { ActiveSession } from "./session";

/**
 * Tokens de API pessoais para integrações (CI, SIEM, scripts). O token age como
 * o usuário que o criou, mas com papel limitado a Leitor ou Analista: aprovar
 * escopo, aceitar risco e administrar usuários continuam exigindo uma pessoa
 * logada. Só o SHA-256 é gravado; o valor aparece uma única vez, na criação.
 */
export const TOKEN_PREFIX = "snt_";
export const TOKEN_ROLES = ["viewer", "analyst"] as const satisfies readonly Role[];
export type TokenRole = (typeof TOKEN_ROLES)[number];
export const TOKEN_LIFETIME_DAYS = [7, 30, 90, 365] as const;
export const MAX_ACTIVE_TOKENS_PER_USER = 20;
const TOUCH_INTERVAL_MS = 5 * 60 * 1000;
const TOKEN_PATTERN = /^snt_[A-Za-z0-9_-]{43}$/;

export type ApiToken = {
  id: string; name: string; prefix: string; role: Role; expiresAt: string; createdAt: string;
  lastUsedAt: string | null; lastUsedIp: string | null; revokedAt: string | null;
  user: { id: string; name: string; email: string };
};

const hashToken = (token: string) => createHash("sha256").update(token).digest("hex");
const iso = (d: Date | null) => d?.toISOString() ?? null;

export class TokenError extends Error {
  constructor(message: string, readonly status = 400) { super(message); }
}

/** Lê "Authorization: Bearer ..."; undefined quando a requisição não usa token. */
export function bearerToken(request: Request): string | undefined {
  const header = request.headers.get("authorization");
  if (!header) return undefined;
  const match = /^Bearer\s+(\S+)\s*$/i.exec(header);
  return match ? match[1] : "";
}

export async function createApiToken(db: Database, input: { organizationId: string; userId: string; userRole: Role; name: string; role: TokenRole; days: number }, now = new Date()) {
  if (!(TOKEN_ROLES as readonly Role[]).includes(input.role)) throw new TokenError("Tokens de API só podem ter papel Leitor ou Analista.");
  if (rankOf(input.role) > rankOf(input.userRole)) throw new TokenError("O token não pode ter mais permissões que o seu papel.", 403);
  if (!(TOKEN_LIFETIME_DAYS as readonly number[]).includes(input.days)) throw new TokenError("Validade não permitida.");
  const [active] = await db.select({ n: count() }).from(apiTokens)
    .where(and(eq(apiTokens.organizationId, input.organizationId), eq(apiTokens.userId, input.userId), isNull(apiTokens.revokedAt), gt(apiTokens.expiresAt, now)));
  if (Number(active?.n ?? 0) >= MAX_ACTIVE_TOKENS_PER_USER) throw new TokenError(`Limite de ${MAX_ACTIVE_TOKENS_PER_USER} tokens ativos. Revogue os que não usa mais.`);
  const token = `${TOKEN_PREFIX}${randomBytes(32).toString("base64url")}`;
  const [row] = await db.insert(apiTokens).values({
    organizationId: input.organizationId, userId: input.userId, name: input.name, role: input.role,
    tokenHash: hashToken(token), prefix: token.slice(0, TOKEN_PREFIX.length + 8),
    expiresAt: new Date(now.getTime() + input.days * 86_400_000), createdAt: now
  }).returning();
  return { token, id: row.id, prefix: row.prefix, expiresAt: row.expiresAt.toISOString() };
}

/**
 * Valida o token: vigente, não revogado, usuário ativo e ainda membro da organização.
 * O papel efetivo é o menor entre o do token e o atual do usuário (rebaixar a pessoa rebaixa os tokens).
 */
export async function validateApiToken(db: Database, token: string | undefined, meta: { ip?: string | null } = {}, now = new Date()): Promise<ActiveSession | null> {
  if (!token || !TOKEN_PATTERN.test(token)) return null;
  const [row] = await db
    .select({ token: apiTokens, user: users, role: memberships.role, requireMfa: organizations.requireMfa })
    .from(apiTokens)
    .innerJoin(users, eq(users.id, apiTokens.userId))
    .innerJoin(memberships, and(eq(memberships.userId, apiTokens.userId), eq(memberships.organizationId, apiTokens.organizationId)))
    .innerJoin(organizations, eq(organizations.id, apiTokens.organizationId))
    .where(and(eq(apiTokens.tokenHash, hashToken(token)), isNull(apiTokens.revokedAt), gt(apiTokens.expiresAt, now)));
  if (!row || row.user.disabled) return null;
  const ip = meta.ip?.slice(0, 64) ?? null;
  if (!row.token.lastUsedAt || now.getTime() - row.token.lastUsedAt.getTime() > TOUCH_INTERVAL_MS || row.token.lastUsedIp !== ip) {
    await db.update(apiTokens).set({ lastUsedAt: now, lastUsedIp: ip }).where(eq(apiTokens.id, row.token.id));
  }
  return {
    id: row.token.id, organizationId: row.token.organizationId, role: lowerRole(row.token.role, row.role),
    user: { id: row.user.id, email: row.user.email, name: row.user.name }, expiresAt: row.token.expiresAt,
    mfaEnabled: Boolean(row.user.totpEnabledAt), mfaEnrollmentRequired: row.requireMfa && !row.user.totpEnabledAt, authMethod: "token"
  };
}

/** Tokens da organização; com userId, só os dessa pessoa. Revogados e vencidos aparecem por 30 dias. */
export async function listApiTokens(db: Database, organizationId: string, filter: { userId?: string } = {}, now = new Date()): Promise<ApiToken[]> {
  const conditions = [eq(apiTokens.organizationId, organizationId), gt(apiTokens.expiresAt, new Date(now.getTime() - 30 * 86_400_000))];
  if (filter.userId) conditions.push(eq(apiTokens.userId, filter.userId));
  const rows = await db.select({ token: apiTokens, user: { id: users.id, name: users.name, email: users.email } })
    .from(apiTokens).innerJoin(users, eq(users.id, apiTokens.userId)).where(and(...conditions)).orderBy(desc(apiTokens.createdAt)).limit(200);
  return rows.map(({ token: t, user }) => ({
    id: t.id, name: t.name, prefix: t.prefix, role: t.role, expiresAt: t.expiresAt.toISOString(), createdAt: t.createdAt.toISOString(),
    lastUsedAt: iso(t.lastUsedAt), lastUsedIp: t.lastUsedIp, revokedAt: iso(t.revokedAt), user
  }));
}

/** Revoga um token da organização (de qualquer pessoa, ou só de `userId` quando informado). */
export async function revokeApiToken(db: Database, organizationId: string, id: string, filter: { userId?: string } = {}, now = new Date()) {
  const conditions = [eq(apiTokens.organizationId, organizationId), eq(apiTokens.id, id), isNull(apiTokens.revokedAt)];
  if (filter.userId) conditions.push(eq(apiTokens.userId, filter.userId));
  const [row] = await db.update(apiTokens).set({ revokedAt: now }).where(and(...conditions)).returning({ id: apiTokens.id, userId: apiTokens.userId, name: apiTokens.name, prefix: apiTokens.prefix });
  return row;
}

/** Revoga todos os tokens de um usuário (ao desativá-lo). */
export async function revokeUserTokens(db: Database, userId: string, now = new Date()) {
  await db.update(apiTokens).set({ revokedAt: now }).where(and(eq(apiTokens.userId, userId), isNull(apiTokens.revokedAt)));
}
