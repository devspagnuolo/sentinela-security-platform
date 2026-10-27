import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { exportOrganization } from "@/db/privacy";
import { withAuth } from "@/lib/auth/http";
export const runtime = "nodejs";

/** Todos os dados da organização em JSON (portabilidade), sem segredos nem hashes. */
export const GET = withAuth("org:manage", async ({ organizationId, repo }) => {
  const data = await exportOrganization(await getDb(), organizationId);
  if (!data) return NextResponse.json({ error: "Organização não encontrada." }, { status: 404 });
  await repo.audit("organization.exported", "organization", organizationId, { members: data.members.length, findings: data.findings.length, auditEntries: data.audit.entries.length });
  return NextResponse.json(data, { headers: { "Cache-Control": "no-store", "Content-Disposition": `attachment; filename=sentinela-organizacao-${data.generatedAt.slice(0, 10)}.json` } });
});
