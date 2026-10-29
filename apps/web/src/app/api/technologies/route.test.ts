import { describe, expect, it } from "vitest";
import { getDb } from "@/db/client";
import { tenantRepository } from "@/db/repository";
import { authorizations } from "@/db/schema";
import { request, signIn } from "@/test/auth";
import { GET } from "./route";

const ctx = {} as never;

describe("/api/technologies", () => {
  it("lista o inventário da própria organização, com filtro por ativo", async () => {
    const a = await signIn("viewer");
    const db = await getDb();
    const [scope] = await db.insert(authorizations).values({ organizationId: a.organizationId, reference: "INV-1", hostnames: ["*.example.com"], status: "approved", validUntil: new Date(Date.now() + 86400000) }).returning();
    const repo = tenantRepository(db, a.organizationId);
    const asset = await repo.createAsset({ name: "Loja", url: "https://loja.example.com", kind: "Web application", owner: "TI", authorizationId: scope.id });
    await repo.recordAssessment(asset.id, "SENTINELA-WEB-003", new Date(), [], new Date(), [{ category: "platform", name: "Shopify", version: null, evidence: "Cabeçalho x-shopify-stage presente" }]);
    const list = await (await GET(request("/api/technologies", { cookie: a.cookie }), ctx)).json();
    expect(list).toEqual([expect.objectContaining({ assetName: "Loja", category: "platform", name: "Shopify", current: true })]);
    expect(await (await GET(request(`/api/technologies?assetId=${asset.id}`, { cookie: a.cookie }), ctx)).json()).toHaveLength(1);
    const b = await signIn("owner");
    expect(await (await GET(request("/api/technologies", { cookie: b.cookie }), ctx)).json()).toEqual([]);
    expect((await GET(request("/api/technologies"), ctx)).status).toBe(401);
  });
});
