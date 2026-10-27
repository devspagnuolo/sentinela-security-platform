import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { ssoStateCookie } from "@/lib/auth/http";
import { findSsoConnectionForEmail, publicOrigin, redirectUriFor, SSO_REQUEST_TTL_MS, startSso } from "@/lib/auth/sso";
export const runtime = "nodejs";

/** Navegação de topo vinda do login: localiza o provedor pelo domínio do e-mail e redireciona para ele. */
export async function GET(request: Request) {
  const origin = publicOrigin(request);
  const email = new URL(request.url).searchParams.get("email")?.trim().slice(0, 254) ?? "";
  const fail = (code: string) => NextResponse.redirect(new URL(`/login?erro=${code}`, origin), 303);
  const db = await getDb();
  const conn = email.includes("@") ? await findSsoConnectionForEmail(db, email) : undefined;
  if (!conn) return fail("sso_unavailable");
  try {
    const { state, url } = await startSso(db, conn, redirectUriFor(origin), email);
    const response = NextResponse.redirect(url.href, 303);
    response.cookies.set(ssoStateCookie(state, SSO_REQUEST_TTL_MS / 1000));
    return response;
  } catch {
    return fail("sso_failed");
  }
}
