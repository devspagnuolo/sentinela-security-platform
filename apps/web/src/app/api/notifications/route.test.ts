import { describe, expect, it } from "vitest";
import { getDb } from "@/db/client";
import { notify } from "@/db/notifications";
import { tenantRepository } from "@/db/repository";
import { authorizations } from "@/db/schema";
import { request, signIn } from "@/test/auth";

const { GET } = await import("./route");
const { POST: READ } = await import("./read/route");
const { PUT: SCHEDULE } = await import("../assets/[id]/schedule/route");
const { GET: RUNS } = await import("../assessments/route");
const { GET: RUN } = await import("../assessments/[id]/route");

const ctx = {} as never;
const idCtx = (id: string) => ({ params: Promise.resolve({ id }) }) as never;

async function assetIn(organizationId: string) {
  const db = await getDb();
  const [scope] = await db.insert(authorizations).values({ organizationId, reference: "AUT-N", hostnames: ["*.example.com"], status: "approved", validUntil: new Date(Date.now() + 86400000) }).returning();
  return tenantRepository(db, organizationId).createAsset({ name: "App", url: "https://app.example.com", kind: "API", owner: "TI", authorizationId: scope.id });
}

describe("/api/notifications", () => {
  it("lista e marca como lidos só os avisos do próprio usuário", async () => {
    const analyst = await signIn("analyst");
    const viewer = await signIn("viewer", analyst.organizationId);
    await notify(await getDb(), analyst.organizationId, { audience: "operators" }, { kind: "test", title: "Aviso", link: "/achados" });

    expect((await GET(request("/api/notifications"), ctx)).status).toBe(401);
    const mine = await (await GET(request("/api/notifications", { cookie: analyst.cookie }), ctx)).json();
    expect(mine).toMatchObject({ unread: 1, items: [{ title: "Aviso", link: "/achados", readAt: null }] });
    expect(await (await GET(request("/api/notifications", { cookie: viewer.cookie }), ctx)).json()).toMatchObject({ unread: 0, items: [] });

    expect((await READ(request("/api/notifications/read", { cookie: analyst.cookie, body: { ids: "x" } }), ctx)).status).toBe(400);
    expect((await READ(request("/api/notifications/read", { cookie: analyst.cookie, body: {}, origin: "https://evil.example" }), ctx)).status).toBe(403);
    expect(await (await READ(request("/api/notifications/read", { cookie: analyst.cookie, body: { ids: [mine.items[0].id] } }), ctx)).json()).toEqual({ marked: 1, unread: 0 });
  });
});

describe("agenda e histórico de avaliações", () => {
  it("Analista agenda; Leitor não; valores fora da lista são recusados", async () => {
    const analyst = await signIn("analyst");
    const viewer = await signIn("viewer", analyst.organizationId);
    const asset = await assetIn(analyst.organizationId);
    const put = (cookie: string, body: unknown) => SCHEDULE(request(`/api/assets/${asset.id}/schedule`, { method: "PUT", cookie, body }), idCtx(asset.id));
    expect((await put(viewer.cookie, { intervalDays: 7 })).status).toBe(403);
    expect((await put(analyst.cookie, { intervalDays: 3 })).status).toBe(400);
    expect(await (await put(analyst.cookie, { intervalDays: 30 })).json()).toMatchObject({ scheduleIntervalDays: 30 });
    expect(await (await put(analyst.cookie, { intervalDays: 0 })).json()).toMatchObject({ scheduleIntervalDays: null, nextAssessmentAt: null });

    const other = await signIn("analyst");
    expect((await put(other.cookie, { intervalDays: 7 })).status).toBe(404);
  });

  it("histórico mostra execuções da organização, inclusive na fila", async () => {
    const analyst = await signIn("analyst");
    const asset = await assetIn(analyst.organizationId);
    const repo = tenantRepository(await getDb(), analyst.organizationId, analyst.user.id);
    const { assessment } = await repo.queueAssessment(asset.id, { method: "TEST" });
    const runs = await (await RUNS(request(`/api/assessments?assetId=${asset.id}`, { cookie: analyst.cookie }), ctx)).json();
    expect(runs).toMatchObject([{ id: assessment.id, status: "queued", assetName: "App", requestedBy: { name: analyst.user.name } }]);
    expect((await RUN(request(`/api/assessments/${assessment.id}`, { cookie: analyst.cookie }), idCtx(assessment.id))).status).toBe(200);

    const other = await signIn("viewer");
    expect(await (await RUNS(request("/api/assessments", { cookie: other.cookie }), ctx)).json()).toEqual([]);
    expect((await RUN(request(`/api/assessments/${assessment.id}`, { cookie: other.cookie }), idCtx(assessment.id))).status).toBe(404);
  });
});
