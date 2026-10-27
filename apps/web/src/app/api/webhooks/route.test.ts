import { describe, expect, it, vi } from "vitest";
import { ORIGIN, request, signIn } from "@/test/auth";

const sent: { url: string; headers: Record<string, string> }[] = [];
vi.mock("@/lib/webhooks", async importOriginal => ({
  ...(await importOriginal<typeof import("@/lib/webhooks")>()),
  httpsTransport: vi.fn(async (url: URL, _body: string, headers: Record<string, string>) => {
    sent.push({ url: url.toString(), headers });
    if (url.hostname === "down.example.com") throw new Error("Conexão recusada.");
    return { status: 202 };
  })
}));

const { GET, POST } = await import("./route");
const { GET: ONE, PATCH, DELETE } = await import("./[id]/route");
const { POST: TEST } = await import("./[id]/test/route");
const { POST: ROTATE } = await import("./[id]/rotate/route");
const { POST: TOKEN } = await import("../tokens/route");
const { getDb } = await import("@/db/client");
const { tenantRepository } = await import("@/db/repository");

const ctx = {} as never;
const idCtx = (id: string) => ({ params: Promise.resolve({ id }) }) as never;
const hook = { name: "Canal de segurança", url: "https://hooks.example.com/sentinela", events: ["assessment.completed", "scope.pending"] };

describe("/api/webhooks", () => {
  it("só Admin e Owner gerenciam; Analista e Leitor não", async () => {
    const analyst = await signIn("analyst");
    const viewer = await signIn("viewer", analyst.organizationId);
    for (const cookie of [analyst.cookie, viewer.cookie]) {
      expect((await GET(request("/api/webhooks", { cookie }), ctx)).status).toBe(403);
      expect((await POST(request("/api/webhooks", { cookie, body: hook }), ctx)).status).toBe(403);
    }
  });

  it("cadastra com segredo exibido uma vez, valida URL e eventos, e audita", async () => {
    const { cookie, organizationId } = await signIn("admin");
    expect((await POST(request("/api/webhooks", { cookie, body: { ...hook, url: "http://hooks.example.com" } }), ctx)).status).toBe(400);
    expect((await POST(request("/api/webhooks", { cookie, body: { ...hook, url: "https://169.254.169.254/latest" } }), ctx)).status).toBe(400);
    expect((await POST(request("/api/webhooks", { cookie, body: { ...hook, events: ["webhook.test"] } }), ctx)).status).toBe(400);
    expect((await POST(request("/api/webhooks", { cookie, body: { ...hook, events: [] } }), ctx)).status).toBe(400);
    expect((await POST(request("/api/webhooks", { cookie, body: hook, origin: "https://evil.example" }), ctx)).status).toBe(403);

    const res = await POST(request("/api/webhooks", { cookie, body: hook }), ctx);
    expect(res.status).toBe(201);
    const { webhook, secret } = await res.json();
    expect(secret).toMatch(/^whsec_/);
    expect(webhook).toMatchObject({ name: hook.name, url: hook.url, events: hook.events, enabled: true });
    const listed = await (await GET(request("/api/webhooks", { cookie }), ctx)).json();
    expect(listed).toHaveLength(1);
    expect(JSON.stringify(listed)).not.toContain(secret);
    expect((await tenantRepository(await getDb(), organizationId).listAudit(1))[0]).toMatchObject({ action: "webhook.created", targetId: webhook.id });
  });

  it("testa na hora, troca segredo, liga/desliga e remove; outra organização não enxerga", async () => {
    const owner = await signIn("owner");
    const outsider = await signIn("owner");
    const { webhook, secret } = await (await POST(request("/api/webhooks", { cookie: owner.cookie, body: hook }), ctx)).json();
    const id = webhook.id;

    const tested = await (await TEST(request(`/api/webhooks/${id}/test`, { cookie: owner.cookie, body: {} }), idCtx(id))).json();
    expect(tested).toMatchObject({ event: "webhook.test", status: "delivered", responseStatus: 202 });
    expect(sent.at(-1)).toMatchObject({ url: hook.url, headers: { "Sentinela-Event": "webhook.test" } });
    expect((await ONE(request(`/api/webhooks/${id}`, { cookie: owner.cookie }), idCtx(id))).status).toBe(200);

    const rotated = await (await ROTATE(request(`/api/webhooks/${id}/rotate`, { cookie: owner.cookie, body: {} }), idCtx(id))).json();
    expect(rotated.secret).toMatch(/^whsec_/);
    expect(rotated.secret).not.toBe(secret);

    expect(await (await PATCH(request(`/api/webhooks/${id}`, { cookie: owner.cookie, method: "PATCH", body: { enabled: false } }), idCtx(id))).json()).toMatchObject({ enabled: false });
    expect((await PATCH(request(`/api/webhooks/${id}`, { cookie: owner.cookie, method: "PATCH", body: {} }), idCtx(id))).status).toBe(400);

    for (const res of [
      await ONE(request(`/api/webhooks/${id}`, { cookie: outsider.cookie }), idCtx(id)),
      await TEST(request(`/api/webhooks/${id}/test`, { cookie: outsider.cookie, body: {} }), idCtx(id)),
      await ROTATE(request(`/api/webhooks/${id}/rotate`, { cookie: outsider.cookie, body: {} }), idCtx(id)),
      await DELETE(request(`/api/webhooks/${id}`, { cookie: outsider.cookie, method: "DELETE" }), idCtx(id))
    ]) expect(res.status).toBe(404);

    expect((await DELETE(request(`/api/webhooks/${id}`, { cookie: owner.cookie, method: "DELETE" }), idCtx(id))).status).toBe(200);
    expect(await (await GET(request("/api/webhooks", { cookie: owner.cookie }), ctx)).json()).toEqual([]);
  });

  it("teste com destino fora do ar mostra o erro", async () => {
    const { cookie } = await signIn("admin");
    const { webhook } = await (await POST(request("/api/webhooks", { cookie, body: { ...hook, url: "https://down.example.com/x" } }), ctx)).json();
    expect(await (await TEST(request(`/api/webhooks/${webhook.id}/test`, { cookie, body: {} }), idCtx(webhook.id))).json()).toMatchObject({ status: "failed", lastError: "Conexão recusada." });
  });

  it("token de API não gerencia webhooks", async () => {
    const { cookie } = await signIn("admin");
    const { token } = await (await TOKEN(request("/api/tokens", { cookie, body: { name: "CI", role: "analyst", days: 7 } }), ctx)).json();
    const res = await GET(new Request(`${ORIGIN}/api/webhooks`, { headers: { Authorization: `Bearer ${token}` } }), ctx);
    expect(res.status).toBe(403);
  });
});
