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
const ctx = {} as never;
const valid = { url: "https://app.example.com", authorized: true, authorizationRef: "AUT-2026-01" };
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

  it("Analista cadastra; aprovação depende da lista do operador; auditoria registra o autor", async () => {
    vi.stubEnv("SENTINELA_ENABLE_SCANNER", "1");
    vi.stubEnv("SENTINELA_ALLOWED_HOSTS", "app.example.com");
    const { cookie, user } = await signIn("analyst");
    const res = await post(cookie, { ...valid, url: "https://APP.example.com/x" });
    expect(res.status).toBe(201);
    const asset = await res.json();
    expect(asset).toMatchObject({ url: "https://app.example.com", name: "app.example.com", approved: true });
    const { getDb } = await import("@/db/client");
    const { tenantRepository } = await import("@/db/repository");
    const { organizationId } = (await (await import("@/lib/auth/session")).validateSession(await getDb(), cookie.split("=")[1]))!;
    const [entry] = await tenantRepository(await getDb(), organizationId).listAudit(1);
    expect(entry).toMatchObject({ action: "asset.created", targetId: asset.id, actorUserId: user.id });
  });

  it("não aprova quando o scanner está desabilitado", async () => {
    vi.stubEnv("SENTINELA_ALLOWED_HOSTS", "app.example.com");
    const { cookie } = await signIn("analyst");
    expect((await (await post(cookie, valid)).json()).approved).toBe(false);
  });

  it("valida entrada e alvo", async () => {
    const { cookie } = await signIn("analyst");
    expect((await post(cookie, "{")).status).toBe(400);
    const noAuth = await post(cookie, { url: valid.url, authorizationRef: "AUT-2026-01" });
    expect(noAuth.status).toBe(400);
    expect((await noAuth.json()).error).toContain("autorização");
    expect((await post(cookie, { ...valid, url: "https://db.internal" })).status).toBe(400);
  });

  it("cada organização vê apenas os próprios ativos", async () => {
    const a = await signIn("analyst");
    const b = await signIn("analyst");
    const created = await (await post(a.cookie, { ...valid, url: "https://so-de-a.example.com" })).json();
    const listB = await (await GET(request("/api/assets", { cookie: b.cookie }), ctx)).json();
    expect(listB.map((x: { id: string }) => x.id)).not.toContain(created.id);
  });
});
