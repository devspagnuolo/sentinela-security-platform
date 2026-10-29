import { afterEach, describe, expect, it, vi } from "vitest";
import { getDb } from "@/db/client";
import { authorizations } from "@/db/schema";
import { request, signIn } from "@/test/auth";
import { GET, POST } from "./route";
import { DELETE, PATCH } from "./[id]/route";
import { POST as SYNC } from "./[id]/sync/route";
import { GET as DISCOVERY } from "../discovery/route";

const ctx = {} as never;
const params = (id: string) => ({ params: Promise.resolve({ id }) });
const zone = "c".repeat(32);
const token = "a1".repeat(20);

/** Responde como a Cloudflare; com `denied`, recusa o token. */
function mockCloudflare(records: { name: string; type: string; content: string }[], denied = false) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async input => {
    const url = new URL(String(input));
    if (url.hostname !== "api.cloudflare.com") throw new Error(`destino inesperado: ${url.hostname}`);
    if (denied) return new Response(JSON.stringify({ success: false, errors: [{ message: "Invalid API Token" }], result: [] }), { status: 403 });
    const body = url.pathname.endsWith("/zones") ? { success: true, result: [{ id: zone, name: "loja.com.br" }], result_info: { page: 1, total_pages: 1 } } : { success: true, result: records, result_info: { page: 1, total_pages: 1 } };
    return new Response(JSON.stringify(body), { status: 200 });
  });
}
const create = (cookie: string, body: unknown) => POST(request("/api/connectors", { cookie, body }), ctx);

afterEach(() => { vi.restoreAllMocks(); });

describe("/api/connectors e /api/discovery", () => {
  it("só Admin e Owner gerenciam conectores; credencial recusada não é gravada", async () => {
    const owner = await signIn("owner");
    const analyst = await signIn("analyst", owner.organizationId);
    expect((await create(analyst.cookie, { name: "CF", credentials: { provider: "cloudflare", apiToken: token } })).status).toBe(403);
    expect((await create(owner.cookie, { name: "CF", credentials: { provider: "gcp", apiToken: token } })).status).toBe(400);
    expect((await create(owner.cookie, { name: "AWS", credentials: { provider: "aws_route53", accessKeyId: "ASIAABCDEFGHIJKLMNOP", secretAccessKey: "x".repeat(40) } })).status).toBe(400);
    mockCloudflare([], true);
    const refused = await create(owner.cookie, { name: "CF", credentials: { provider: "cloudflare", apiToken: token } });
    expect(refused.status).toBe(400);
    expect((await refused.json()).error).toContain("Zone:Read");
    expect(await (await GET(request("/api/connectors", { cookie: owner.cookie }), ctx)).json()).toEqual([]);
  });

  it("cadastra, sincroniza e mostra os hostnames classificados; nunca devolve a credencial", async () => {
    const owner = await signIn("owner");
    const viewer = await signIn("viewer", owner.organizationId);
    await (await getDb()).insert(authorizations).values({ organizationId: owner.organizationId, reference: "LOJA-1", hostnames: ["www.loja.com.br"], status: "approved", validUntil: new Date(Date.now() + 86400000) });
    const fetch = mockCloudflare([{ name: "www.loja.com.br", type: "A", content: "93.184.216.34" }, { name: "admin.loja.com.br", type: "A", content: "93.184.216.35" }]);
    const res = await create(owner.cookie, { name: "Cloudflare da loja", credentials: { provider: "cloudflare", apiToken: token } });
    expect(res.status).toBe(201);
    const { connector, sync } = await res.json();
    expect(connector).toMatchObject({ name: "Cloudflare da loja", provider: "cloudflare", credentialHint: `token …${token.slice(-4)}`, hostCount: 2, lastError: null });
    expect(sync).toMatchObject({ ok: true, newOutOfScope: ["admin.loja.com.br"] });
    for (const call of fetch.mock.calls) expect(call[1]?.method).toBe("GET");
    const list = await (await GET(request("/api/connectors", { cookie: owner.cookie }), ctx)).text();
    expect(list).not.toContain(token);

    const hosts = await (await DISCOVERY(request("/api/discovery", { cookie: viewer.cookie }), ctx)).json();
    expect(hosts.map((h: { hostname: string; status: string; authorization: { reference: string } | null }) => [h.hostname, h.status, h.authorization?.reference ?? null]))
      .toEqual([["admin.loja.com.br", "out_of_scope", null], ["www.loja.com.br", "in_scope", "LOJA-1"]]);

    expect((await SYNC(request(`/api/connectors/${connector.id}/sync`, { cookie: owner.cookie, body: {} }), params(connector.id))).status).toBe(200);
    expect((await PATCH(request(`/api/connectors/${connector.id}`, { cookie: owner.cookie, body: { enabled: false }, method: "PATCH" }), params(connector.id))).status).toBe(200);
    expect((await PATCH(request(`/api/connectors/${connector.id}`, { cookie: owner.cookie, body: { credentials: { provider: "aws_route53", accessKeyId: "AKIAABCDEFGHIJKLMNOP", secretAccessKey: "x".repeat(40) } }, method: "PATCH" }), params(connector.id))).status).toBe(400);
    const other = await signIn("owner");
    expect((await DELETE(request(`/api/connectors/${connector.id}`, { cookie: other.cookie, method: "DELETE" }), params(connector.id))).status).toBe(404);
    expect((await DELETE(request(`/api/connectors/${connector.id}`, { cookie: owner.cookie, method: "DELETE" }), params(connector.id))).status).toBe(200);
    expect(await (await DISCOVERY(request("/api/discovery", { cookie: viewer.cookie }), ctx)).json()).toEqual([]);
  });
});
