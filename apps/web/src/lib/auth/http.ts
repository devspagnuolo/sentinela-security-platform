import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { tenantRepository, type TenantRepository } from "@/db/repository";
import { can, type Permission } from "./rbac";
import { SESSION_TTL_MS, validateSession, type ActiveSession } from "./session";

const secureCookies = () => process.env.NODE_ENV === "production" && process.env.SENTINELA_INSECURE_COOKIES !== "1";
/** Em produção o prefixo __Host- obriga Secure, Path=/ e ausência de Domain. */
export const sessionCookieName = () => secureCookies() ? "__Host-sentinela_session" : "sentinela_session";

export function sessionCookie(token: string, expiresAt: Date) {
  return { name: sessionCookieName(), value: token, httpOnly: true, secure: secureCookies(), sameSite: "lax" as const, path: "/", expires: expiresAt, maxAge: Math.floor(SESSION_TTL_MS / 1000) };
}
export function clearedSessionCookie() {
  return { name: sessionCookieName(), value: "", httpOnly: true, secure: secureCookies(), sameSite: "lax" as const, path: "/", maxAge: 0 };
}

export function readCookie(header: string | null, name: string): string | undefined {
  for (const part of header?.split(";") ?? []) {
    const index = part.indexOf("=");
    if (index > 0 && part.slice(0, index).trim() === name) return decodeURIComponent(part.slice(index + 1).trim());
  }
  return undefined;
}

export const requestToken = (request: Request) => readCookie(request.headers.get("cookie"), sessionCookieName());

export function clientMeta(request: Request) {
  const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return { ip: forwarded || request.headers.get("x-real-ip"), userAgent: request.headers.get("user-agent") };
}

/**
 * Proteção CSRF para métodos que alteram estado: a requisição precisa vir da
 * própria origem (cabeçalho Origin igual ao host ou listado em SENTINELA_PUBLIC_ORIGIN).
 */
export function isSameOrigin(request: Request): boolean {
  if (["GET", "HEAD", "OPTIONS"].includes(request.method)) return true;
  const origin = request.headers.get("origin");
  if (!origin) return false;
  const allowed = new Set([new URL(request.url).origin, ...(process.env.SENTINELA_PUBLIC_ORIGIN ?? "").split(",").map(o => o.trim()).filter(Boolean)]);
  const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host");
  if (host) allowed.add(`${request.headers.get("x-forwarded-proto") ?? new URL(request.url).protocol.replace(":", "")}://${host}`);
  return allowed.has(origin);
}

export type AuthContext = ActiveSession & { repo: TenantRepository };

export const unauthorized = () => NextResponse.json({ error: "Autenticação necessária." }, { status: 401 });
export const forbidden = () => NextResponse.json({ error: "Seu papel não permite esta ação." }, { status: 403 });
export const crossOrigin = () => NextResponse.json({ error: "Origem da requisição não permitida." }, { status: 403 });

/** Envolve um route handler exigindo sessão válida, permissão e mesma origem. */
export function withAuth<C>(permission: Permission, handler: (auth: AuthContext, request: Request, context: C) => Promise<Response>) {
  return async (request: Request, context: C): Promise<Response> => {
    if (!isSameOrigin(request)) return crossOrigin();
    const db = await getDb();
    const session = await validateSession(db, requestToken(request));
    if (!session) return unauthorized();
    const repo = tenantRepository(db, session.organizationId, session.user.id);
    if (!can(session.role, permission)) {
      await repo.audit("auth.forbidden", "permission", permission, { method: request.method, path: new URL(request.url).pathname });
      return forbidden();
    }
    return handler({ ...session, repo }, request, context);
  };
}
