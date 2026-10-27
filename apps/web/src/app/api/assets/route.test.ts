import { beforeEach, describe, expect, it, vi } from "vitest";
import { request, signIn } from "@/test/auth";

vi.mock("@/lib/scanner", () => ({
  validateTarget: vi.fn(async (raw: string) => {
    const url = new URL(raw);
    if (url.hostname.endsWith(".internal")) throw new Error("O alvo resolve para endereço não público ou não verificável.");
    return { url, addresses: [{ address: "93.184.216.34", family: 4 }] };
  })
}));

const { GET, POST } = await import("./route");
const { getDb } = await import("@/db/client");
const { tenantRepository } = await import("@/db/repository");
const { authorizations } = await import("@/db/schema");
const ctx = {} as never;
const valid = { url: "https://app.example.com", authorizationId: "00000000-0000-4000-8000-000000000000" };

/** Autorização de escopo aprovada (ou no estado pedido) cobrindo *.example.com. */
async function scope(organizationId: string, status: "approved" | "pending" = "approved") {
  const [row] = await (await getDb()).insert(authorizations).values({ organizationId, reference: "AUT-2026-01", hostnames: ["*.example.com"], status, validUntil: new Date(Date.now() + 86400000) }).returning();
  return row.id;
}
const post = (cookie: string | undefined, body: unknown, origin?: string | null) => POST(request("/api/assets", { cookie, body, origin }), ctx);

describe("/api/assets", () => {
  beforeEach(() => { vi.unstubAllEnvs(); });

  it("exige sessão", async () => {
    expect((await GET(request("/api/assets"), ctx)).status).toBe(401);
    expect((await post(undefined, valid)).status).toBe(401);
  });

  it("Leitor lista mas não cadastra", async () => {
    const { cookie } = await signIn("viewer");
    expect((await GET(request("/api/assets", { cookie }), ctx)).status).toBe(200);
    expect((await post(cookie, valid)).status).toBe(403);
  });

  it("recusa escrita sem Origin ou de outra origem (CSRF)", async () => {
    const { cookie } = await signIn("analyst");
    expect((await post(cookie, valid, null)).status).toBe(403);
    expect((await post(cookie, valid, "https://evil.example")).status).toBe(403);
  });

  it("Analista cadastra sob escopo vigente; auditoria registra o autor", async () => {
    const { cookie, user, organizationId } = await signIn("analyst");
    const authorizationId = await scope(organizationId);
    const res = await post(cookie, { ...valid, authorizationId, url: "https://APP.example.com/x" });
    expect(res.status).toBe(201);
    const asset = await res.json();
    expect(asset).toMatchObject({ url: "https://app.example.com", name: "app.example.com", authorizationRef: "AUT-2026-01", scopeOk: true });
    const [entry] = await tenantRepository(await getDb(), organizationId).listAudit(1);
    expect(entry).toMatchObject({ action: "asset.created", targetId: asset.id, actorUserId: user.id });
  });

  it("recusa hostname fora do escopo, escopo pendente e escopo de outra organização", async () => {
    const { cookie, organizationId } = await signIn("analyst");
    const authorizationId = await scope(organizationId);
    expect((await (await post(cookie, { ...valid, authorizationId, url: "https://outro.example.org" })).json()).error).toContain("não está entre os autorizados");
    const pending = await scope(organizationId, "pending");
    expect((await (await post(cookie, { ...valid, authorizationId: pending })).json()).error).toContain("ainda não foi aprovada");
    const other = await signIn("analyst");
    expect((await post(other.cookie, { ...valid, authorizationId })).status).toBe(400);
  });

  it("valida entrada e alvo", async () => {
    const { cookie } = await signIn("analyst");
    expect((await post(cookie, "{")).status).toBe(400);
    const noAuth = await post(cookie, { url: valid.url });
    expect(noAuth.status).toBe(400);
    expect((await noAuth.json()).error).toContain("autorização");
    expect((await post(cookie, { ...valid, url: "https://db.internal" })).status).toBe(400);
  });

  it("cada organização vê apenas os próprios ativos", async () => {
    const a = await signIn("analyst");
    const b = await signIn("analyst");
    const created = await (await post(a.cookie, { ...valid, authorizationId: await scope(a.organizationId), url: "https://so-de-a.example.com" })).json();
    const listB = await (await GET(request("/api/assets", { cookie: b.cookie }), ctx)).json();
    expect(listB.map((x: { id: string }) => x.id)).not.toContain(created.id);
  });
});
