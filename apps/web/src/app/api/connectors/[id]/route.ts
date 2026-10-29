import { NextResponse } from "next/server";
import { z } from "zod";
import { getDb } from "@/db/client";
import { connectorRepository, syncConnector } from "@/db/connectors";
import { withAuth } from "@/lib/auth/http";
import { connectorUpdateSchema, parseJson } from "@/lib/validation";
export const runtime = "nodejs";

type Params = { params: Promise<{ id: string }> };
const notFound = () => NextResponse.json({ error: "Conector não encontrado." }, { status: 404 });

/** Renomeia, liga/desliga ou troca a credencial (a nova é testada na hora). */
export const PATCH = withAuth("integration:manage", async ({ organizationId, user, repo }, request, { params }: Params) => {
  const { id } = await params;
  if (!z.uuid().safeParse(id).success) return notFound();
  const parsed = await parseJson(request, connectorUpdateSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  const db = await getDb();
  const connectors = connectorRepository(db, organizationId, user.id);
  const current = await connectors.row(id);
  if (!current) return notFound();
  if (parsed.data.credentials && parsed.data.credentials.provider !== current.provider) return NextResponse.json({ error: "A credencial precisa ser do mesmo provedor do conector." }, { status: 400 });
  const updated = await connectors.update(id, parsed.data);
  const sync = parsed.data.credentials ? await syncConnector(db, (await connectors.row(id))!) : undefined;
  await repo.audit("connector.updated", "connector", id, { name: parsed.data.name, enabled: parsed.data.enabled, credentialReplaced: Boolean(parsed.data.credentials), ...(sync && !sync.ok && { error: sync.error }) });
  return NextResponse.json({ connector: sync ? (await connectors.list()).find(c => c.id === id) : updated, sync });
});

/** Remove o conector e os hostnames que ele descobriu (os ativos já cadastrados continuam). */
export const DELETE = withAuth("integration:manage", async ({ organizationId, user, repo }, _request, { params }: Params) => {
  const { id } = await params;
  if (!z.uuid().safeParse(id).success) return notFound();
  const removed = await connectorRepository(await getDb(), organizationId, user.id).remove(id);
  if (!removed) return notFound();
  await repo.audit("connector.deleted", "connector", id, { name: removed.name, provider: removed.provider });
  return NextResponse.json({ ok: true });
});
