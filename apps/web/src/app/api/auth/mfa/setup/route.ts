import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { withAuth } from "@/lib/auth/http";
import { beginTotpSetup } from "@/lib/auth/mfa";
export const runtime = "nodejs";

export const POST = withAuth("asset:read", async ({ user, mfaEnabled }) => {
  if (mfaEnabled) return NextResponse.json({ error: "A verificação em duas etapas já está ativa." }, { status: 409 });
  return NextResponse.json(await beginTotpSetup(await getDb(), user.id, user.email), { headers: { "Cache-Control": "no-store" } });
}, { allowDuringMfaEnrollment: true });
