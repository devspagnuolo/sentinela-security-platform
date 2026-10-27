import { describe, expect, it } from "vitest";
import { request, signIn } from "@/test/auth";
import { GET as exportOrg } from "./export/route";
import { GET as getRetention, PUT as putRetention } from "./retention/route";
import { GET as exportMine } from "../auth/export-data/route";
import { POST as anonymize } from "../users/[id]/anonymize/route";
import { PATCH as patchUser } from "../users/[id]/route";

const ctx = {} as never;
const params = (id: string) => ({ params: Promise.resolve({ id }) });
const retention = (cookie: string, body: unknown) => putRetention(request("/api/organization/retention", { cookie, body, method: "PUT" }), ctx);
const anon = (cookie: string, id: string, body: unknown) => anonymize(request(`/api/users/${id}/anonymize`, { cookie, body }), params(id));

describe("LGPD: retenção, exportações e anonimização", () => {
  it("só o Owner altera a retenção, e só para prazos permitidos", async () => {
    const owner = await signIn("owner");
    const admin = await signIn("admin", owner.organizationId);
    expect((await retention(admin.cookie, { auditRetentionDays: 365 })).status).toBe(403);
    expect((await retention(owner.cookie, { auditRetentionDays: 30 })).status).toBe(400);
    expect((await retention(owner.cookie, { assessmentRetentionDays: 45 })).status).toBe(400);
    expect((await retention(owner.cookie, {})).status).toBe(400);
    const r = await retention(owner.cookie, { auditRetentionDays: 365, assessmentRetentionDays: 180, closedFindingRetentionDays: null });
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ auditRetentionDays: 365, assessmentRetentionDays: 180, closedFindingRetentionDays: null, scopeContactRetentionDays: 180 });
    expect(await (await getRetention(request("/api/organization/retention", { cookie: owner.cookie }), ctx)).json()).toMatchObject({ auditRetentionDays: 365 });
  });

  it("qualquer pessoa exporta os próprios dados; a organização inteira, só o Owner", async () => {
    const owner = await signIn("owner");
    const viewer = await signIn("viewer", owner.organizationId);
    const mine = await exportMine(request("/api/auth/export-data", { cookie: viewer.cookie }), ctx);
    expect(mine.status).toBe(200);
    expect(mine.headers.get("content-disposition")).toContain("sentinela-meus-dados-");
    expect((await mine.json()).profile.email).toBe(viewer.user.email);
    expect((await exportOrg(request("/api/organization/export", { cookie: viewer.cookie }), ctx)).status).toBe(403);
    const org = await exportOrg(request("/api/organization/export", { cookie: owner.cookie }), ctx);
    expect(org.status).toBe(200);
    expect((await org.json()).members).toHaveLength(2);
  });

  it("anonimiza com confirmação do e-mail, encerra o acesso e bloqueia alterações depois", async () => {
    const owner = await signIn("owner");
    const admin = await signIn("admin", owner.organizationId);
    const viewer = await signIn("viewer", owner.organizationId);
    expect((await anon(admin.cookie, viewer.user.id, { confirmEmail: viewer.user.email })).status).toBe(403);
    expect((await anon(owner.cookie, owner.user.id, { confirmEmail: owner.user.email })).status).toBe(403);
    expect((await anon(owner.cookie, viewer.user.id, { confirmEmail: "outro@example.com" })).status).toBe(400);
    expect((await anon(owner.cookie, viewer.user.id, { confirmEmail: viewer.user.email.toUpperCase() })).status).toBe(200);
    expect((await exportMine(request("/api/auth/export-data", { cookie: viewer.cookie }), ctx)).status).toBe(401);
    expect((await patchUser(request(`/api/users/${viewer.user.id}`, { cookie: owner.cookie, body: { disabled: false }, method: "PATCH" }), params(viewer.user.id))).status).toBe(409);
    expect((await anon(owner.cookie, viewer.user.id, { confirmEmail: viewer.user.email })).status).toBe(400);
  });
});
