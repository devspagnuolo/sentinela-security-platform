import { eq } from "drizzle-orm";
import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { users } from "@/db/schema";
import { withAuth } from "@/lib/auth/http";
import { hashPassword, passwordPolicyError, verifyPassword } from "@/lib/auth/password";
import { revokeUserSessions } from "@/lib/auth/session";
import { changePasswordSchema, parseJson } from "@/lib/validation";
export const runtime = "nodejs";

export const POST = withAuth("asset:read", async ({ user, id: sessionId, repo }, request) => {
  const parsed = await parseJson(request, changePasswordSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  const db = await getDb();
  const [row] = await db.select({ passwordHash: users.passwordHash }).from(users).where(eq(users.id, user.id));
  if (!row?.passwordHash || !(await verifyPassword(parsed.data.currentPassword, row.passwordHash))) return NextResponse.json({ error: "Senha atual incorreta." }, { status: 400 });
  const policy = passwordPolicyError(parsed.data.newPassword, user);
  if (policy) return NextResponse.json({ error: policy }, { status: 400 });
  await db.update(users).set({ passwordHash: await hashPassword(parsed.data.newPassword), passwordChangedAt: new Date() }).where(eq(users.id, user.id));
  await revokeUserSessions(db, user.id, sessionId);
  await repo.audit("auth.password_changed", "user", user.id);
  return NextResponse.json({ ok: true });
}, { allowDuringMfaEnrollment: true });
