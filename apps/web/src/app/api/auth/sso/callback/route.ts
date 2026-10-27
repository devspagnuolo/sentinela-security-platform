import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { clearedSsoStateCookie, clientMeta, readCookie, sessionCookie, ssoStateCookieName } from "@/lib/auth/http";
import { completeSso, publicOrigin, redirectUriFor } from "@/lib/auth/sso";
export const runtime = "nodejs";

/** Retorno do provedor OIDC (redirect_uri registrado). */
export async function GET(request: Request) {
  const origin = publicOrigin(request);
  const params = new URL(request.url).searchParams;
  // A URL vista pelo servidor pode ser interna (atrás de proxy): reconstrói a partir da origem pública.
  const callbackUrl = new URL(redirectUriFor(origin));
  params.forEach((value, key) => callbackUrl.searchParams.append(key, value));
  const result = params.has("error")
    ? { ok: false as const, error: "sso_failed" as const }
    : await completeSso(await getDb(), { state: params.get("state"), cookieState: readCookie(request.headers.get("cookie"), ssoStateCookieName()), callbackUrl, meta: clientMeta(request) });
  const response = NextResponse.redirect(new URL(result.ok ? "/" : `/login?erro=${result.error}`, origin), 303);
  response.cookies.set(clearedSsoStateCookie());
  if (result.ok) response.cookies.set(sessionCookie(result.token, result.expiresAt));
  return response;
}
