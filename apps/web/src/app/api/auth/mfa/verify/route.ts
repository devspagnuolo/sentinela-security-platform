import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { clientMeta, crossOrigin, isSameOrigin, sessionCookie } from "@/lib/auth/http";
import { completeMfaLogin } from "@/lib/auth/mfa";
import { mfaVerifySchema, parseJson } from "@/lib/validation";
export const runtime = "nodejs";

/** Segunda etapa do login: desafio emitido em /api/auth/login + código TOTP ou de recuperação. */
export async function POST(request: Request) {
  if (!isSameOrigin(request)) return crossOrigin();
  const parsed = await parseJson(request, mfaVerifySchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  const result = await completeMfaLogin(await getDb(), parsed.data.challenge, parsed.data.code, clientMeta(request));
  if (!result.ok) return NextResponse.json({ error: result.error }, { status: 401 });
  const response = NextResponse.json({ ok: true, method: result.method });
  response.cookies.set(sessionCookie(result.token, result.expiresAt));
  return response;
}
