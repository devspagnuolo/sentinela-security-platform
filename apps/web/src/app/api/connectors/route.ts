import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { connectorRepository, MAX_CONNECTORS, syncConnector } from "@/db/connectors";
import { withAuth } from "@/lib/auth/http";
import { connectorSchema, parseJson } from "@/lib/validation";
export const runtime = "nodejs";

export const GET = withAuth("integration:manage", async ({ organizationId }) =>
  NextResponse.json(await connectorRepository(await getDb(), organizationId).list(), { headers: { "Cache-Control": "no-store" } }));

/** Cadastra o conector e faz a primeira sincronização na hora: credencial que não funciona não é gravada. */
export const POST = withAuth("integration:manage", async ({ organizationId, user, repo }, request) => {
  const parsed = await parseJson(request, connectorSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  const db = await getDb();
  const connectors = connectorRepository(db, organizationId, user.id);
  if ((await connectors.list()).length >= MAX_CONNECTORS) return NextResponse.json({ error: `Limite de ${MAX_CONNECTORS} conectores por organização.` }, { status: 409 });
  const row = await connectors.create(parsed.data);
  const result = await syncConnector(db, row);
  if (!result.ok) {
    await connectors.remove(row.id);
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  await repo.audit("connector.created", "connector", row.id, { name: row.name, provider: row.provider, credential: row.credentialHint, hosts: result.hosts });
  const connector = (await connectors.list()).find(c => c.id === row.id);
  return NextResponse.json({ connector, sync: result }, { status: 201 });
});
