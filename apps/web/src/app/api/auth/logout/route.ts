import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { clearedSessionCookie, crossOrigin, isSameOrigin, requestToken } from "@/lib/auth/http";
import { revokeSession, validateSession } from "@/lib/auth/session";
import { tenantRepository } from "@/db/repository";
export const runtime = "nodejs";

export async function POST(request: Request) {
  if (!isSameOrigin(request)) return crossOrigin();
  const db = await getDb();
  const token = requestToken(request);
  const session = await validateSession(db, token);
  if (session) await tenantRepository(db, session.organizationId, session.user.id).audit("auth.logout", "user", session.user.id);
  await revokeSession(db, token);
  const response = NextResponse.json({ ok: true });
  response.cookies.set(clearedSessionCookie());
  return response;
}
