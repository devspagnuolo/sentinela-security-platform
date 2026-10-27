import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/scanner", () => ({
  validateTarget: vi.fn(async (raw: string) => {
    const url = new URL(raw);
    if (url.hostname.endsWith(".internal")) throw new Error("O alvo resolve para endereço não público ou não verificável.");
    return { url, addresses: [{ address: "93.184.216.34", family: 4 }] };
  })
}));

const { POST } = await import("./route");
const { store } = await import("@/lib/store");

const post = (body: unknown) => POST(new Request("http://localhost/api/assets", { method: "POST", headers: { "Content-Type": "application/json" }, body: typeof body === "string" ? body : JSON.stringify(body) }));

describe("POST /api/assets", () => {
  beforeEach(() => { vi.unstubAllEnvs(); });

  it("cadastra ativo e só aprova host presente na lista com scanner habilitado", async () => {
    vi.stubEnv("SENTINELA_ENABLE_SCANNER", "1");
    vi.stubEnv("SENTINELA_ALLOWED_HOSTS", "app.example.com");
    const res = await post({ url: "https://APP.example.com/x", authorized: true, authorizationRef: "AUT-2026-01" });
    expect(res.status).toBe(201);
    const asset = await res.json();
    expect(asset).toMatchObject({ url: "https://app.example.com", name: "app.example.com", approved: true });
    expect(store.assets[0].id).toBe(asset.id);
  });

  it("não aprova quando o scanner está desabilitado", async () => {
    vi.stubEnv("SENTINELA_ALLOWED_HOSTS", "app.example.com");
    const res = await post({ url: "https://app.example.com", authorized: true, authorizationRef: "AUT-2026-01" });
    expect((await res.json()).approved).toBe(false);
  });

  it("rejeita JSON inválido, autorização ausente e alvo não público", async () => {
    expect((await post("{")).status).toBe(400);
    const noAuth = await post({ url: "https://app.example.com", authorizationRef: "AUT-2026-01" });
    expect(noAuth.status).toBe(400);
    expect((await noAuth.json()).error).toContain("autorização");
    const internal = await post({ url: "https://db.internal", authorized: true, authorizationRef: "AUT-2026-01" });
    expect(internal.status).toBe(400);
  });
});
