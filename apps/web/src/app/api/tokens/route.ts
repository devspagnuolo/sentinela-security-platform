import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { withAuth } from "@/lib/auth/http";
import { can } from "@/lib/auth/rbac";
import { createApiToken, listApiTokens, TokenError } from "@/lib/auth/tokens";
import { apiTokenSchema, parseJson } from "@/lib/validation";
export const runtime = "nodejs";

/** Os próprios tokens; com ?scope=all, os de toda a organização (para quem gerencia usuários). */
export const GET = withAuth("asset:read", async ({ user, role, organizationId }, request) => {
  const all = new URL(request.url).searchParams.get("scope") === "all";
  if (all && !can(role, "user:manage")) return NextResponse.json({ error: "Seu papel não permite ver os tokens de outras pessoas." }, { status: 403 });
  return NextResponse.json(await listApiTokens(await getDb(), organizationId, all ? {} : { userId: user.id }), { headers: { "Cache-Control": "no-store" } });
});

/** Cria um token pessoal. O valor só aparece nesta resposta. */
export const POST = withAuth("asset:read", async ({ user, role, organizationId, repo }, request) => {
  const parsed = await parseJson(request, apiTokenSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  try {
    const created = await createApiToken(await getDb(), { organizationId, userId: user.id, userRole: role, ...parsed.data });
    await repo.audit("token.created", "api_token", created.id, { name: parsed.data.name, role: parsed.data.role, prefix: created.prefix, expiresAt: created.expiresAt });
    return NextResponse.json(created, { status: 201, headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    if (error instanceof TokenError) return NextResponse.json({ error: error.message }, { status: error.status });
    throw error;
  }
});
