import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { withAuth } from "@/lib/auth/http";
import { disableMfa } from "@/lib/auth/mfa";
import { confirmPassword } from "@/lib/auth/reauth";
import { parseJson, passwordConfirmSchema } from "@/lib/validation";
export const runtime = "nodejs";

export const POST = withAuth("asset:read", async ({ user, repo }, request) => {
  const parsed = await parseJson(request, passwordConfirmSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  const db = await getDb();
  if (!(await confirmPassword(db, user.id, parsed.data.password))) return NextResponse.json({ error: "Senha incorreta." }, { status: 400 });
  await disableMfa(db, user.id);
  await repo.audit("auth.mfa_disabled", "user", user.id, { by: "self" });
  return NextResponse.json({ ok: true });
}, { allowDuringMfaEnrollment: true });
