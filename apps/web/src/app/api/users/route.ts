import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { memberRepository } from "@/db/users";
import { withAuth } from "@/lib/auth/http";
import { passwordPolicyError } from "@/lib/auth/password";
import { canManageRole } from "@/lib/auth/rbac";
import { createUserSchema, parseJson } from "@/lib/validation";
export const runtime = "nodejs";

export const GET = withAuth("user:read", async ({ organizationId }) =>
  NextResponse.json(await memberRepository(await getDb(), organizationId).list(), { headers: { "Cache-Control": "no-store" } }));

export const POST = withAuth("user:manage", async ({ organizationId, role, repo }, request) => {
  const parsed = await parseJson(request, createUserSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  const input = parsed.data;
  if (!canManageRole(role, input.role)) return NextResponse.json({ error: "Seu papel não permite criar usuários com este papel." }, { status: 403 });
  const policy = passwordPolicyError(input.password, input);
  if (policy) return NextResponse.json({ error: policy }, { status: 400 });
  try {
    const member = await memberRepository(await getDb(), organizationId).create(input);
    await repo.audit("user.created", "user", member.id, { email: member.email, role: member.role });
    return NextResponse.json(member, { status: 201 });
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "Não foi possível criar o usuário." }, { status: 409 });
  }
});
