import { describe, expect, it } from "vitest";
import { getDb } from "@/db/client";
import { tenantRepository } from "@/db/repository";
import { request, signIn } from "@/test/auth";
import { GET as HEALTH } from "../health/route";
import { GET } from "./route";

const ctx = {} as never;

describe("GET /api/audit", () => {
  it("pagina por seq, filtra por categoria e mostra o autor", async () => {
    const { cookie, organizationId, user } = await signIn("admin");
    const repo = tenantRepository(await getDb(), organizationId, user.id);
    for (let i = 0; i < 5; i++) await repo.audit("asset.created", "asset", `a${i}`, { i });
    await repo.audit("auth.logout", "user", user.id);

    const first = await (await GET(request("/api/audit?limit=3", { cookie }), ctx)).json();
    expect(first.map((e: { action: string }) => e.action)).toEqual(["auth.logout", "asset.created", "asset.created"]);
    expect(first[0]).toMatchObject({ actorName: user.name, actorEmail: user.email });
    const next = await (await GET(request(`/api/audit?limit=10&before=${first.at(-1).seq}`, { cookie }), ctx)).json();
    expect(next.map((e: { targetId: string }) => e.targetId)).toEqual(["a2", "a1", "a0"]);

    const auth = await (await GET(request("/api/audit?category=auth", { cookie }), ctx)).json();
    expect(auth.every((e: { action: string }) => e.action.startsWith("auth."))).toBe(true);
    expect((await GET(request("/api/audit?category=x%25", { cookie }), ctx)).status).toBe(400);
    expect((await GET(request("/api/audit?before=abc", { cookie }), ctx)).status).toBe(400);
  });

  it("exporta CSV com fórmulas neutralizadas e registra a exportação", async () => {
    const { cookie, organizationId, user } = await signIn("owner");
    const repo = tenantRepository(await getDb(), organizationId, user.id);
    await repo.audit("asset.created", "asset", "x", { name: "=cmd|' /C calc'!A0" });
    const res = await GET(request("/api/audit?format=csv&category=asset", { cookie }), ctx);
    expect(res.headers.get("content-type")).toContain("text/csv");
    const text = await res.text();
    expect(text).toContain("asset.created");
    expect(text).not.toMatch(/(^|,)"=/m);
    const [last] = await repo.listAudit(1);
    expect(last).toMatchObject({ action: "export.audit_downloaded" });
  });

  it("exige audit:read", async () => {
    const { cookie } = await signIn("analyst");
    expect((await GET(request("/api/audit", { cookie }), ctx)).status).toBe(403);
  });
});

describe("GET /api/health", () => {
  it("responde sem autenticação e confere o banco com ?ready", async () => {
    expect(await (await HEALTH(request("/api/health"))).json()).toEqual({ status: "ok" });
    expect(await (await HEALTH(request("/api/health?ready=1"))).json()).toEqual({ status: "ok", database: "ok" });
  });
});
