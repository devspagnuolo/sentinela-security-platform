import { describe, expect, it } from "vitest";
import { eq } from "drizzle-orm";
import { getDb } from "@/db/client";
import { tenantRepository } from "@/db/repository";
import { apiTokens, organizations } from "@/db/schema";
import { ORIGIN, request, signIn } from "@/test/auth";

const { GET, POST } = await import("./route");
const { DELETE } = await import("./[id]/route");
const { GET: ASSETS } = await import("../assets/route");
const { GET: SCOPES, POST: CREATE_SCOPE } = await import("../scopes/route");
const { POST: APPROVE } = await import("../scopes/[id]/approve/route");
const { GET: NOTIFICATIONS } = await import("../notifications/route");
const { GET: ME } = await import("../auth/me/route");
const { GET: USERS } = await import("../users/route");
const { PATCH: UPDATE_USER } = await import("../users/[id]/route");

const ctx = {} as never;
const idCtx = (id: string) => ({ params: Promise.resolve({ id }) }) as never;
const scope = { reference: "AUT-API", hostnames: ["api.example.com"], validUntil: new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10) };

/** Requisição com token no cabeçalho Authorization, sem cookie nem Origin. */
function bearer(path: string, token: string, init: { method?: string; body?: unknown } = {}) {
  const headers = new Headers({ "Content-Type": "application/json", Authorization: `Bearer ${token}` });
  return new Request(`${ORIGIN}${path}`, { method: init.method ?? (init.body === undefined ? "GET" : "POST"), headers, body: init.body === undefined ? undefined : JSON.stringify(init.body) });
}
async function createToken(cookie: string, body: Record<string, unknown> = {}) {
  return POST(request("/api/tokens", { cookie, body: { name: "CI", role: "analyst", days: 30, ...body } }), ctx);
}

describe("tokens de API", () => {
  it("cria token exibido uma vez; só o hash é gravado", async () => {
    const { cookie, organizationId } = await signIn("analyst");
    const res = await createToken(cookie);
    expect(res.status).toBe(201);
    const { token, id, prefix } = await res.json();
    expect(token).toMatch(/^snt_[A-Za-z0-9_-]{43}$/);
    expect(token.startsWith(prefix)).toBe(true);
    const [row] = await (await getDb()).select().from(apiTokens).where(eq(apiTokens.id, id));
    expect(JSON.stringify(row)).not.toContain(token);
    const listed = await (await GET(request("/api/tokens", { cookie }), ctx)).json();
    expect(listed).toHaveLength(1);
    expect(JSON.stringify(listed)).not.toContain(token);
    expect((await tenantRepository(await getDb(), organizationId).listAudit(1))[0]).toMatchObject({ action: "token.created", metadata: { role: "analyst", prefix } });
  });

  it("papel do token: só Leitor ou Analista e nunca acima do papel da pessoa", async () => {
    const viewer = await signIn("viewer");
    expect((await createToken(viewer.cookie)).status).toBe(403);
    expect((await createToken(viewer.cookie, { role: "viewer" })).status).toBe(201);
    const admin = await signIn("admin");
    expect((await createToken(admin.cookie, { role: "admin" })).status).toBe(400);
    expect((await createToken(admin.cookie, { days: 3650 })).status).toBe(400);
  });

  it("autentica rotas de negócio sem cookie nem Origin e registra o token na auditoria", async () => {
    const { cookie, organizationId } = await signIn("analyst");
    const { token, id } = await (await createToken(cookie)).json();
    expect((await ASSETS(bearer("/api/assets", token), ctx)).status).toBe(200);
    const created = await CREATE_SCOPE(bearer("/api/scopes", token, { body: scope }), ctx);
    expect(created.status).toBe(201);
    const [entry] = await tenantRepository(await getDb(), organizationId).listAudit(1);
    expect(entry).toMatchObject({ action: "scope.created", metadata: { via: "api_token", apiTokenId: id } });
    expect(await (await ME(bearer("/api/auth/me", token), ctx)).json()).toMatchObject({ role: "analyst", authMethod: "token" });
    const [row] = await (await getDb()).select().from(apiTokens).where(eq(apiTokens.id, id));
    expect(row.lastUsedAt).not.toBeNull();
  });

  it("rotas de conta, usuários e tokens exigem pessoa logada", async () => {
    const { cookie } = await signIn("analyst");
    const { token } = await (await createToken(cookie)).json();
    for (const res of [await NOTIFICATIONS(bearer("/api/notifications", token), ctx), await GET(bearer("/api/tokens", token), ctx), await POST(bearer("/api/tokens", token, { body: { name: "x", role: "viewer", days: 7 } }), ctx)]) {
      expect(res.status).toBe(403);
      expect((await res.json()).error).toContain("tokens de API não são aceitos");
    }
  });

  it("token de Admin vira Analista: não aprova escopo nem lista usuários", async () => {
    const admin = await signIn("admin");
    const { token } = await (await createToken(admin.cookie)).json();
    const analyst = await signIn("analyst", admin.organizationId);
    const pending = await (await CREATE_SCOPE(request("/api/scopes", { cookie: analyst.cookie, body: scope }), ctx)).json();
    expect((await APPROVE(bearer(`/api/scopes/${pending.id}/approve`, token, { body: {} }), idCtx(pending.id))).status).toBe(403);
    expect((await USERS(bearer("/api/users", token), ctx)).status).toBe(403);
    expect((await APPROVE(request(`/api/scopes/${pending.id}/approve`, { cookie: admin.cookie, body: {} }), idCtx(pending.id))).status).toBe(200);
  });

  it("recusa token inválido, revogado, vencido e de pessoa rebaixada ou desativada", async () => {
    const owner = await signIn("owner");
    const analyst = await signIn("analyst", owner.organizationId);
    const { token, id } = await (await createToken(analyst.cookie)).json();
    expect((await SCOPES(bearer("/api/scopes", "snt_invalido"), ctx)).status).toBe(401);
    expect((await SCOPES(bearer("/api/scopes", `${token}x`), ctx)).status).toBe(401);

    // Rebaixado a Leitor: o token passa a valer como Leitor.
    expect((await UPDATE_USER(request(`/api/users/${analyst.user.id}`, { cookie: owner.cookie, method: "PATCH", body: { role: "viewer" } }), idCtx(analyst.user.id))).status).toBe(200);
    expect((await SCOPES(bearer("/api/scopes", token), ctx)).status).toBe(200);
    expect((await CREATE_SCOPE(bearer("/api/scopes", token, { body: scope }), ctx)).status).toBe(403);

    // Vencido.
    const db = await getDb();
    await db.update(apiTokens).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(apiTokens.id, id));
    expect((await SCOPES(bearer("/api/scopes", token), ctx)).status).toBe(401);
    await db.update(apiTokens).set({ expiresAt: new Date(Date.now() + 86400000) }).where(eq(apiTokens.id, id));

    // Desativado: tokens revogados de vez (não voltam ao reativar).
    await UPDATE_USER(request(`/api/users/${analyst.user.id}`, { cookie: owner.cookie, method: "PATCH", body: { disabled: true } }), idCtx(analyst.user.id));
    await UPDATE_USER(request(`/api/users/${analyst.user.id}`, { cookie: owner.cookie, method: "PATCH", body: { disabled: false } }), idCtx(analyst.user.id));
    expect((await SCOPES(bearer("/api/scopes", token), ctx)).status).toBe(401);
  });

  it("organização exige MFA: token de quem não cadastrou não funciona", async () => {
    const { cookie, organizationId } = await signIn("analyst");
    const { token } = await (await createToken(cookie)).json();
    await (await getDb()).update(organizations).set({ requireMfa: true }).where(eq(organizations.id, organizationId));
    expect((await SCOPES(bearer("/api/scopes", token), ctx)).status).toBe(403);
    expect((await ME(bearer("/api/auth/me", token), ctx)).status).toBe(403);
  });

  it("cada um revoga os próprios; quem gerencia usuários vê e revoga todos; outra organização não", async () => {
    const admin = await signIn("admin");
    const analyst = await signIn("analyst", admin.organizationId);
    const other = await signIn("analyst", admin.organizationId);
    const outsider = await signIn("owner");
    const { token, id } = await (await createToken(analyst.cookie)).json();
    expect((await DELETE(request(`/api/tokens/${id}`, { cookie: other.cookie, method: "DELETE" }), idCtx(id))).status).toBe(404);
    expect((await DELETE(request(`/api/tokens/${id}`, { cookie: outsider.cookie, method: "DELETE" }), idCtx(id))).status).toBe(404);
    expect((await GET(request("/api/tokens?scope=all", { cookie: analyst.cookie }), ctx)).status).toBe(403);
    expect(await (await GET(request("/api/tokens?scope=all", { cookie: admin.cookie }), ctx)).json()).toMatchObject([{ id, user: { id: analyst.user.id } }]);
    expect((await DELETE(request(`/api/tokens/${id}`, { cookie: admin.cookie, method: "DELETE" }), idCtx(id))).status).toBe(200);
    expect((await SCOPES(bearer("/api/scopes", token), ctx)).status).toBe(401);
    expect((await DELETE(request(`/api/tokens/${id}`, { cookie: admin.cookie, method: "DELETE" }), idCtx(id))).status).toBe(404);
  });

  it("limite de tokens ativos por pessoa", async () => {
    const { cookie, user, organizationId } = await signIn("viewer");
    const db = await getDb();
    await db.insert(apiTokens).values(Array.from({ length: 20 }, (_, i) => ({ organizationId, userId: user.id, name: `t${i}`, tokenHash: `${user.id}-${i}`, prefix: "snt_x", role: "viewer" as const, expiresAt: new Date(Date.now() + 86400000) })));
    expect((await createToken(cookie, { role: "viewer" })).status).toBe(400);
  });
});
