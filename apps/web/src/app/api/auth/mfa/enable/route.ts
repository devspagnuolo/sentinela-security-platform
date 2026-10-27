import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { withAuth } from "@/lib/auth/http";
import { confirmTotpSetup } from "@/lib/auth/mfa";
import { mfaCodeSchema, parseJson } from "@/lib/validation";
export const runtime = "nodejs";

export const POST = withAuth("asset:read", async ({ user, repo }, request) => {
  const parsed = await parseJson(request, mfaCodeSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  const recoveryCodes = await confirmTotpSetup(await getDb(), user.id, parsed.data.code);
  if (!recoveryCodes) return NextResponse.json({ error: "Código inválido. Confira o horário do celular e tente o código atual." }, { status: 400 });
  await repo.audit("auth.mfa_enabled", "user", user.id);
  return NextResponse.json({ recoveryCodes }, { headers: { "Cache-Control": "no-store" } });
}, { allowDuringMfaEnrollment: true });
