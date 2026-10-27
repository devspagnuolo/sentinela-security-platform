import { eq } from "drizzle-orm";
import { NextResponse } from "next/server";
import { z } from "zod";
import { getDb } from "@/db/client";
import { users } from "@/db/schema";
import { memberRepository } from "@/db/users";
import { withAuth } from "@/lib/auth/http";
import { hashPassword, passwordPolicyError } from "@/lib/auth/password";
import { canManageRole } from "@/lib/auth/rbac";
import { revokeUserSessions } from "@/lib/auth/session";
import { parseJson, updateUserSchema } from "@/lib/validation";
export const runtime = "nodejs";

type Params = { params: Promise<{ id: string }> };
const deny = (error: string, status = 403) => NextResponse.json({ error }, { status });

export const PATCH = withAuth("user:manage", async ({ organizationId, role, user: actor, repo }, request, { params }: Params) => {
  const { id } = await params;
  if (!z.uuid().safeParse(id).success) return deny("Usuário não encontrado.", 404);
  const parsed = await parseJson(request, updateUserSchema);
  if ("error" in parsed) return deny(parsed.error, 400);
  const changes = parsed.data;
  const db = await getDb();
  const members = memberRepository(db, organizationId);
  const target = await members.get(id);
  if (!target) return deny("Usuário não encontrado.", 404);
  if (!canManageRole(role, target.role) || (changes.role && !canManageRole(role, changes.role))) return deny("Seu papel não permite alterar este usuário.");
  if (target.id === actor.id && (changes.role || changes.disabled)) return deny("Você não pode alterar o próprio papel nem desativar a própria conta.");
  const losesOwner = target.role === "owner" && !target.disabled && ((changes.role && changes.role !== "owner") || changes.disabled);
  if (losesOwner && (await members.activeOwnerCount()) <= 1) return deny("A organização precisa manter ao menos um Owner ativo.", 409);
  if (changes.password !== undefined) {
    const policy = passwordPolicyError(changes.password, target);
    if (policy) return deny(policy, 400);
    await db.update(users).set({ passwordHash: await hashPassword(changes.password), passwordChangedAt: new Date(), failedLoginCount: 0, lockedUntil: null }).where(eq(users.id, id));
  }
  const updated = await members.update(id, { role: changes.role, disabled: changes.disabled, name: changes.name });
  if (changes.disabled || changes.password !== undefined || changes.role) await revokeUserSessions(db, id);
  await repo.audit("user.updated", "user", id, { role: changes.role, disabled: changes.disabled, name: changes.name, passwordReset: changes.password !== undefined });
  return NextResponse.json(updated);
});
