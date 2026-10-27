import { NextResponse } from "next/server";
import { z } from "zod";
import { getDb } from "@/db/client";
import { AnonymizeError, anonymizeUser } from "@/db/privacy";
import { memberRepository } from "@/db/users";
import { withAuth } from "@/lib/auth/http";
import { anonymizeSchema, parseJson } from "@/lib/validation";
export const runtime = "nodejs";

type Params = { params: Promise<{ id: string }> };
const deny = (error: string, status = 403) => NextResponse.json({ error }, { status });

/** Eliminação dos dados pessoais (LGPD, art. 18, VI). Só o Owner, e com o e-mail digitado como confirmação. */
export const POST = withAuth("org:manage", async ({ organizationId, user: actor, repo }, request, { params }: Params) => {
  const { id } = await params;
  if (!z.uuid().safeParse(id).success) return deny("Usuário não encontrado.", 404);
  if (id === actor.id) return deny("Você não pode anonimizar a própria conta.");
  const parsed = await parseJson(request, anonymizeSchema);
  if ("error" in parsed) return deny(parsed.error, 400);
  const db = await getDb();
  const target = await memberRepository(db, organizationId).get(id);
  if (!target) return deny("Usuário não encontrado.", 404);
  if (parsed.data.confirmEmail.toLowerCase() !== target.email.toLowerCase()) return deny("O e-mail digitado não confere com o da pessoa.", 400);
  try {
    await anonymizeUser(db, organizationId, id);
  } catch (error) {
    if (error instanceof AnonymizeError) return deny(error.message, error.status);
    throw error;
  }
  // Sem nome nem e-mail na auditoria: o registro só diz que a conta foi anonimizada.
  await repo.audit("user.anonymized", "user", id, { role: target.role });
  return NextResponse.json({ ok: true });
});
