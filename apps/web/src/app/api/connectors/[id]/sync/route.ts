import { NextResponse } from "next/server";
import { z } from "zod";
import { getDb } from "@/db/client";
import { connectorRepository, syncConnector } from "@/db/connectors";
import { withAuth } from "@/lib/auth/http";
export const runtime = "nodejs";

/** Sincroniza agora (sem esperar o ciclo diário do worker). */
export const POST = withAuth("integration:manage", async ({ organizationId, user, repo }, _request, { params }: { params: Promise<{ id: string }> }) => {
  const { id } = await params;
  if (!z.uuid().safeParse(id).success) return NextResponse.json({ error: "Conector não encontrado." }, { status: 404 });
  const db = await getDb();
  const row = await connectorRepository(db, organizationId, user.id).row(id);
  if (!row) return NextResponse.json({ error: "Conector não encontrado." }, { status: 404 });
  const result = await syncConnector(db, row);
  await repo.audit("connector.synced", "connector", id, result.ok ? { hosts: result.hosts, newHosts: result.newHosts, newOutOfScope: result.newOutOfScope.length } : { error: result.error });
  return NextResponse.json(result, { status: result.ok ? 200 : 502 });
});
