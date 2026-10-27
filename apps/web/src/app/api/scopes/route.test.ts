import { describe, expect, it, vi } from "vitest";
import { getDb } from "@/db/client";
import { tenantRepository } from "@/db/repository";
import { memberRepository } from "@/db/users";
import { createSession } from "@/lib/auth/session";
import { sessionCookieName } from "@/lib/auth/http";
import { request, signIn, TEST_PASSWORD } from "@/test/auth";

const assess = vi.fn();
vi.mock("@/lib/scanner", () => ({
  SCANNER_METHOD_ID: "TEST",
  assess: (...args: unknown[]) => assess(...args),
  validateTarget: async (raw: string) => ({ url: new URL(raw), addresses: [{ address: "93.184.216.34", family: 4 }] })
}));

const { GET: LIST, POST: CREATE } = await import("./route");
const { POST: APPROVE } = await import("./[id]/approve/route");
const { POST: REVOKE } = await import("./[id]/revoke/route");
const { POST: ASSET } = await import("../assets/route");
const { POST: ASSESS } = await import("../assets/[id]/assess/route");
const { GET: FINDINGS } = await import("../findings/route");
const { PATCH: TRIAGE } = await import("../findings/[id]/route");
const { GET: EVENTS } = await import("../findings/[id]/events/route");

const ctx = {} as never;
const idCtx = (id: string) => ({ params: Promise.resolve({ id }) }) as never;
const inDays = (n: number) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10);
const body = { reference: "CT-2026-07", clientName: "ACME", hostnames: ["*.acme.example"], excludedHostnames: ["legado.acme.example"], validUntil: inDays(30) };

/** Membro extra na mesma organização, com cookie de sessão. */
async function member(organizationId: string, role: "owner" | "admin" | "analyst" | "viewer") {
  const db = await getDb();
  const user = await memberRepository(db, organizationId).create({ email: `${role}-${crypto.randomUUID()}@example.com`, name: `${role} extra`, role, password: TEST_PASSWORD });
  return { user, cookie: `${sessionCookieName()}=${(await createSession(db, { userId: user.id, organizationId })).token}` };
}

describe("autorizações de escopo", () => {
  it("analista cadastra pendente; admin aprova; quem cadastrou não aprova (exceto Owner)", async () => {
    const analyst = await signIn("analyst");
    const created = await CREATE(request("/api/scopes", { cookie: analyst.cookie, body }), ctx);
    expect(created.status).toBe(201);
    const scope = await created.json();
    expect(scope).toMatchObject({ status: "pending", state: "pending", clientName: "ACME", createdBy: { id: analyst.user.id } });
    expect((await APPROVE(request(`/api/scopes/${scope.id}/approve`, { cookie: analyst.cookie, body: {} }), idCtx(scope.id))).status).toBe(403);

    const admin = await member(analyst.organizationId, "admin");
    const approved = await (await APPROVE(request(`/api/scopes/${scope.id}/approve`, { cookie: admin.cookie, body: {} }), idCtx(scope.id))).json();
    expect(approved).toMatchObject({ status: "approved", state: "active", approvedBy: { id: admin.user.id } });
    expect((await APPROVE(request(`/api/scopes/${scope.id}/approve`, { cookie: admin.cookie, body: {} }), idCtx(scope.id))).status).toBe(409);

    // Admin que cadastrou não aprova o próprio; Owner pode, e fica registrado.
    const own = await (await CREATE(request("/api/scopes", { cookie: admin.cookie, body }), ctx)).json();
    expect((await APPROVE(request(`/api/scopes/${own.id}/approve`, { cookie: admin.cookie, body: {} }), idCtx(own.id))).status).toBe(403);
    const owner = await member(analyst.organizationId, "owner");
    const ownerScope = await (await CREATE(request("/api/scopes", { cookie: owner.cookie, body }), ctx)).json();
    expect((await APPROVE(request(`/api/scopes/${ownerScope.id}/approve`, { cookie: owner.cookie, body: {} }), idCtx(ownerScope.id))).status).toBe(200);
    const [audit] = await tenantRepository(await getDb(), analyst.organizationId).listAudit(1);
    expect(audit).toMatchObject({ action: "scope.approved", metadata: { selfApproved: true } });
  });

  it("valida o corpo e isola organizações", async () => {
    const a = await signIn("admin");
    expect((await CREATE(request("/api/scopes", { cookie: a.cookie, body: { ...body, hostnames: ["*"] } }), ctx)).status).toBe(400);
    const scope = await (await CREATE(request("/api/scopes", { cookie: a.cookie, body }), ctx)).json();
    const b = await signIn("owner");
    expect((await (await LIST(request("/api/scopes", { cookie: b.cookie }), ctx)).json()).map((s: { id: string }) => s.id)).not.toContain(scope.id);
    expect((await APPROVE(request(`/api/scopes/${scope.id}/approve`, { cookie: b.cookie, body: {} }), idCtx(scope.id))).status).toBe(404);
    const viewer = await signIn("viewer", a.organizationId);
    expect((await CREATE(request("/api/scopes", { cookie: viewer.cookie, body }), ctx)).status).toBe(403);
  });

  it("scanner só roda com escopo vigente; revogar bloqueia na hora; triagem com permissões", async () => {
    const analyst = await signIn("analyst");
    const admin = await member(analyst.organizationId, "admin");
    const scope = await (await CREATE(request("/api/scopes", { cookie: analyst.cookie, body }), ctx)).json();
    await APPROVE(request(`/api/scopes/${scope.id}/approve`, { cookie: admin.cookie, body: {} }), idCtx(scope.id));
    const asset = await (await ASSET(request("/api/assets", { cookie: analyst.cookie, body: { url: "https://app.acme.example", authorizationId: scope.id } }), ctx)).json();
    expect(asset.scopeOk).toBe(true);
    expect((await ASSET(request("/api/assets", { cookie: analyst.cookie, body: { url: "https://legado.acme.example", authorizationId: scope.id } }), ctx)).status).toBe(400);

    assess.mockResolvedValueOnce([{ title: "HSTS ausente", severity: "low", category: "HTTP Headers", description: "d", evidence: "e", recommendation: "r", references: [] }]);
    const run = await ASSESS(request(`/api/assets/${asset.id}/assess`, { cookie: analyst.cookie, body: {} }), idCtx(asset.id));
    expect(run.status).toBe(200);
    const [finding] = (await run.json()).findings;

    // Triagem: analista marca falso positivo, mas não aceita risco.
    const accept = { status: "accepted", reason: "Mitigado por WAF.", acceptedUntil: inDays(60) };
    expect((await TRIAGE(request(`/api/findings/${finding.id}`, { method: "PATCH", cookie: analyst.cookie, body: accept }), idCtx(finding.id))).status).toBe(403);
    const accepted = await (await TRIAGE(request(`/api/findings/${finding.id}`, { method: "PATCH", cookie: admin.cookie, body: accept }), idCtx(finding.id))).json();
    expect(accepted).toMatchObject({ status: "accepted", statusReason: "Mitigado por WAF." });
    const open = await (await FINDINGS(request("/api/findings?status=open", { cookie: analyst.cookie }), ctx)).json();
    expect(open.map((f: { id: string }) => f.id)).not.toContain(finding.id);
    const events = await (await EVENTS(request(`/api/findings/${finding.id}/events`, { cookie: analyst.cookie }), idCtx(finding.id))).json();
    expect(events).toMatchObject([{ fromStatus: "open", toStatus: "accepted", actorName: admin.user.name }]);

    // Revogada: a próxima avaliação é bloqueada antes de qualquer requisição ao alvo.
    expect((await REVOKE(request(`/api/scopes/${scope.id}/revoke`, { cookie: admin.cookie, body: { reason: "Contrato encerrado." } }), idCtx(scope.id))).status).toBe(200);
    assess.mockClear();
    const blocked = await ASSESS(request(`/api/assets/${asset.id}/assess`, { cookie: analyst.cookie, body: {} }), idCtx(asset.id));
    expect(blocked.status).toBe(403);
    expect((await blocked.json()).error).toContain("revogada");
    expect(assess).not.toHaveBeenCalled();
  });
});
