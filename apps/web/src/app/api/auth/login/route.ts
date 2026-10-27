import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { clientMeta, crossOrigin, isSameOrigin, sessionCookie } from "@/lib/auth/http";
import { login } from "@/lib/auth/login";
import { loginSchema, parseJson } from "@/lib/validation";
export const runtime = "nodejs";

export async function POST(request: Request) {
  if (!isSameOrigin(request)) return crossOrigin();
  const parsed = await parseJson(request, loginSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  const result = await login(await getDb(), parsed.data.email, parsed.data.password, clientMeta(request));
  if (result.ok === false) return NextResponse.json({ error: result.error }, { status: 401 });
  if (result.ok === "mfa") return NextResponse.json({ mfaRequired: true, challenge: result.challenge });
  const response = NextResponse.json({ ok: true });
  response.cookies.set(sessionCookie(result.token, result.expiresAt));
  return response;
}
