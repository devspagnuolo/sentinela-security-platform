import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { withAuth } from "@/lib/auth/http";
import { replaceRecoveryCodes } from "@/lib/auth/mfa";
import { confirmPassword } from "@/lib/auth/reauth";
import { parseJson, passwordConfirmSchema } from "@/lib/validation";
export const runtime = "nodejs";

/** Gera um novo conjunto de códigos de recuperação, invalidando os anteriores. */
export const POST = withAuth("asset:read", async ({ user, repo, mfaEnabled }, request) => {
  if (!mfaEnabled) return NextResponse.json({ error: "Ative a verificação em duas etapas primeiro." }, { status: 409 });
  const parsed = await parseJson(request, passwordConfirmSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  const db = await getDb();
  if (!(await confirmPassword(db, user.id, parsed.data.password))) return NextResponse.json({ error: "Senha incorreta." }, { status: 400 });
  const recoveryCodes = await replaceRecoveryCodes(db, user.id);
  await repo.audit("auth.recovery_codes_regenerated", "user", user.id);
  return NextResponse.json({ recoveryCodes }, { headers: { "Cache-Control": "no-store" } });
});
