import { NextResponse } from "next/server";
import { z } from "zod";
import { getDb } from "@/db/client";
import { withAuth } from "@/lib/auth/http";
import { can } from "@/lib/auth/rbac";
import { revokeApiToken } from "@/lib/auth/tokens";
export const runtime = "nodejs";

/** Revoga o próprio token; quem gerencia usuários revoga qualquer token da organização. */
export const DELETE = withAuth("asset:read", async ({ user, role, organizationId, repo }, _request, { params }: { params: Promise<{ id: string }> }) => {
  const { id } = await params;
  if (!z.uuid().safeParse(id).success) return NextResponse.json({ error: "Token não encontrado." }, { status: 404 });
  const revoked = await revokeApiToken(await getDb(), organizationId, id, can(role, "user:manage") ? {} : { userId: user.id });
  if (!revoked) return NextResponse.json({ error: "Token não encontrado ou já revogado." }, { status: 404 });
  await repo.audit("token.revoked", "api_token", id, { name: revoked.name, prefix: revoked.prefix, ownerId: revoked.userId });
  return NextResponse.json({ ok: true });
});
