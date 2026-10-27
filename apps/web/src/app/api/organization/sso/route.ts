import { eq } from "drizzle-orm";
import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { ssoConnections } from "@/db/schema";
import { withAuth } from "@/lib/auth/http";
import { getSsoConnection, isInsecureIssuerAllowed, oidcConfiguration, publicOrigin, redirectUriFor, ssoView } from "@/lib/auth/sso";
import { decrypt, encrypt } from "@/lib/crypto";
import { parseJson, ssoConfigSchema } from "@/lib/validation";
export const runtime = "nodejs";

export const GET = withAuth("org:manage", async ({ organizationId }, request) =>
  NextResponse.json(ssoView(await getSsoConnection(await getDb(), organizationId), redirectUriFor(publicOrigin(request)))));

/** Cria ou atualiza o provedor; antes de gravar, confere que o emissor responde à descoberta OIDC. */
export const PUT = withAuth("org:manage", async ({ organizationId, repo }, request) => {
  const parsed = await parseJson(request, ssoConfigSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  const input = parsed.data;
  if (new URL(input.issuer).protocol !== "https:" && !isInsecureIssuerAllowed(input.issuer)) return NextResponse.json({ error: "O emissor precisa usar HTTPS." }, { status: 400 });
  const db = await getDb();
  const others = await db.select({ organizationId: ssoConnections.organizationId, allowedDomains: ssoConnections.allowedDomains }).from(ssoConnections);
  const taken = input.allowedDomains.find(d => others.some(o => o.organizationId !== organizationId && o.allowedDomains.includes(d)));
  if (taken) return NextResponse.json({ error: `O domínio ${taken} já está associado a outra organização.` }, { status: 409 });
  const current = await getSsoConnection(db, organizationId);
  const clientSecret = input.clientSecret ?? (current && decrypt(current.clientSecret));
  if (!clientSecret) return NextResponse.json({ error: "Informe o client secret." }, { status: 400 });
  try {
    await oidcConfiguration({ issuer: input.issuer, clientId: input.clientId, clientSecret });
  } catch {
    return NextResponse.json({ error: "Não foi possível ler a configuração OIDC do emissor. Confira a URL do issuer." }, { status: 400 });
  }
  const values = { issuer: input.issuer, clientId: input.clientId, clientSecret: encrypt(clientSecret), allowedDomains: [...new Set(input.allowedDomains)], enabled: input.enabled, enforced: input.enforced, jitRole: input.jitRole };
  const [conn] = await db.insert(ssoConnections).values({ organizationId, ...values }).onConflictDoUpdate({ target: ssoConnections.organizationId, set: values }).returning();
  await repo.audit("sso.updated", "organization", organizationId, { issuer: conn.issuer, clientId: conn.clientId, allowedDomains: conn.allowedDomains, enabled: conn.enabled, enforced: conn.enforced, jitRole: conn.jitRole, secretChanged: Boolean(input.clientSecret) });
  return NextResponse.json(ssoView(conn, redirectUriFor(publicOrigin(request))));
});

export const DELETE = withAuth("org:manage", async ({ organizationId, repo }) => {
  await (await getDb()).delete(ssoConnections).where(eq(ssoConnections.organizationId, organizationId));
  await repo.audit("sso.deleted", "organization", organizationId);
  return NextResponse.json({ ok: true });
});
