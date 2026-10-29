import { describe, expect, it } from "vitest";
import { getDb } from "@/db/client";
import { tenantRepository } from "@/db/repository";
import { authorizations } from "@/db/schema";
import { request, signIn } from "@/test/auth";

const { GET } = await import("./route");
const { GET: EXPORT } = await import("../../export/route");
const ctx = {} as never;
const idCtx = (id: string) => ({ params: Promise.resolve({ id }) }) as never;

async function assessedAsset(organizationId: string) {
  const db = await getDb();
  const [scope] = await db.insert(authorizations).values({ organizationId, reference: "CT-PDF", hostnames: ["*.example.com"], status: "approved", validUntil: new Date(Date.now() + 86400000) }).returning();
  const repo = tenantRepository(db, organizationId);
  const asset = await repo.createAsset({ name: "Portal São João", url: "https://portal.example.com", kind: "Web application", owner: "TI", authorizationId: scope.id });
  await repo.recordAssessment(asset.id, "SENTINELA-WEB-002", new Date(), [
    { title: "Certificado TLS não confiável", severity: "high", category: "TLS", description: "Expirado → renovar 🔒", evidence: "CERT_HAS_EXPIRED", recommendation: "Renove.", references: ["CWE-295"] }
  ], new Date(), [{ category: "server", name: "nginx", version: "1.24.0", evidence: "Server: nginx/1.24.0" }]);
  return asset;
}

describe("relatórios e exportação", () => {
  it("PDF gerado no servidor, com auditoria do formato", async () => {
    const { cookie, organizationId } = await signIn("viewer");
    const asset = await assessedAsset(organizationId);
    const res = await GET(request(`/api/reports/${asset.id}?format=pdf`, { cookie }), idCtx(asset.id));
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/pdf");
    expect(res.headers.get("content-disposition")).toMatch(/filename=sentinela-report-portal-sao-joao-\d{4}-\d{2}-\d{2}\.pdf/);
    const pdf = Buffer.from(await res.arrayBuffer());
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
    expect(pdf.length).toBeGreaterThan(2000);
    const [entry] = await tenantRepository(await getDb(), organizationId).listAudit(1);
    expect(entry).toMatchObject({ action: "report.generated", metadata: { format: "pdf" } });

    const json = await (await GET(request(`/api/reports/${asset.id}?format=json`, { cookie }), idCtx(asset.id))).json();
    expect(json.assessment.method.id).toBe("SENTINELA-WEB-002");
    expect(json.technologies).toEqual([{ category: "Servidor web", name: "nginx", version: "1.24.0", evidence: "Server: nginx/1.24.0" }]);
    expect(await (await GET(request(`/api/reports/${asset.id}?format=html`, { cookie }), idCtx(asset.id))).text()).toContain("Tecnologias identificadas");
    expect((await GET(request(`/api/reports/${asset.id}?format=docx`, { cookie }), idCtx(asset.id))).status).toBe(400);
  });

  it("outra organização não gera o relatório", async () => {
    const a = await signIn("viewer");
    const asset = await assessedAsset(a.organizationId);
    const b = await signIn("owner");
    expect((await GET(request(`/api/reports/${asset.id}?format=pdf`, { cookie: b.cookie }), idCtx(asset.id))).status).toBe(404);
  });

  it("exporta XLSX para quem tem export:download; Leitor não", async () => {
    const analyst = await signIn("analyst");
    await assessedAsset(analyst.organizationId);
    const res = await EXPORT(request("/api/export?format=xlsx", { cookie: analyst.cookie }), ctx);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("spreadsheetml");
    expect(Buffer.from(await res.arrayBuffer()).subarray(0, 2).toString()).toBe("PK");
    const viewer = await signIn("viewer", analyst.organizationId);
    expect((await EXPORT(request("/api/export?format=xlsx", { cookie: viewer.cookie }), ctx)).status).toBe(403);
  });
});
