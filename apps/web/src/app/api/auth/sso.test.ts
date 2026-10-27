import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { eq } from "drizzle-orm";
import { getDb } from "@/db/client";
import { memberships, organizations, users } from "@/db/schema";
import { memberRepository } from "@/db/users";
import type { Role } from "@/lib/auth/rbac";
import { createSession } from "@/lib/auth/session";
import { sessionCookieName, ssoStateCookieName } from "@/lib/auth/http";
import { SSO_REQUIRED } from "@/lib/auth/login";
import { request, TEST_PASSWORD } from "@/test/auth";
import { startOidcProvider } from "@/test/oidc-provider";
import { GET as ASSETS } from "../assets/route";
import { GET as SSO_GET, PUT as SSO_PUT } from "../organization/sso/route";
import { POST as LOGIN } from "./login/route";
import { GET as ME } from "./me/route";
import { GET as CALLBACK } from "./sso/callback/route";
import { GET as START } from "./sso/start/route";

const ctx = {} as never;
let provider: Awaited<ReturnType<typeof startOidcProvider>>;
let n = 0;
beforeAll(async () => { provider = await startOidcProvider(); });
afterAll(async () => { await provider.close(); });

/** Organização com domínio de e-mail próprio, um Owner logado e o SSO configurado. */
async function ssoOrg(options: { enforced?: boolean; jitRole?: "analyst" | "viewer" | null } = {}) {
  const db = await getDb();
  const domain = `org${Date.now()}${++n}.test`;
  const [org] = await db.insert(organizations).values({ slug: `sso-${domain}`, name: "Org SSO" }).returning();
  const members = memberRepository(db, org.id);
  const add = (role: Role, local: string) => members.create({ email: `${local}@${domain}`, name: local, role, password: TEST_PASSWORD });
  const owner = await add("owner", "owner");
  const ownerCookie = `${sessionCookieName()}=${(await createSession(db, { userId: owner.id, organizationId: org.id })).token}`;
  const res = await SSO_PUT(request("/api/organization/sso", { method: "PUT", cookie: ownerCookie, body: {
    issuer: provider.issuer, clientId: provider.clientId, clientSecret: provider.clientSecret, allowedDomains: [domain],
    enabled: true, enforced: options.enforced ?? false, jitRole: options.jitRole ?? null
  } }), ctx);
  expect(res.status).toBe(200);
  return { org, domain, owner, ownerCookie, add };
}

/** Executa o fluxo completo no navegador simulado: start → provedor → callback. */
async function ssoLogin(email: string, claims: Record<string, unknown>, opts: { dropCookie?: boolean } = {}) {
  const start = await START(request(`/api/auth/sso/start?email=${encodeURIComponent(email)}`));
  expect(start.status).toBe(303);
  const location = start.headers.get("location")!;
  if (location.includes("/login?erro=")) return { location, cookie: "" };
  const stateCookie = start.headers.get("set-cookie")!.split(";")[0];
  expect(stateCookie.startsWith(`${ssoStateCookieName()}=`)).toBe(true);
  const { code, state } = provider.authorize(location, claims);
  const callback = await CALLBACK(request(`/api/auth/sso/callback?code=${code}&state=${state}`, { cookie: opts.dropCookie ? undefined : stateCookie }));
  const sessionCookie = callback.headers.getSetCookie().find(c => c.startsWith(`${sessionCookieName()}=`) && !c.startsWith(`${sessionCookieName()}=;`));
  return { location: callback.headers.get("location")!, cookie: sessionCookie?.split(";")[0] ?? "", state, stateCookie };
}

describe("SSO (OIDC)", () => {
  it("só o Owner configura; segredo nunca é devolvido; emissor inválido é recusado", async () => {
    const { ownerCookie, add, org, domain } = await ssoOrg();
    const view = await (await SSO_GET(request("/api/organization/sso", { cookie: ownerCookie }), ctx)).json();
    expect(view).toMatchObject({ configured: true, issuer: provider.issuer, enabled: true, redirectUri: "http://localhost/api/auth/sso/callback" });
    expect(JSON.stringify(view)).not.toContain(provider.clientSecret);

    const admin = await add("admin", "admin");
    const adminCookie = `${sessionCookieName()}=${(await createSession(await getDb(), { userId: admin.id, organizationId: org.id })).token}`;
    expect((await SSO_GET(request("/api/organization/sso", { cookie: adminCookie }), ctx)).status).toBe(403);

    const put = (body: Record<string, unknown>) => SSO_PUT(request("/api/organization/sso", { method: "PUT", cookie: ownerCookie, body: { issuer: provider.issuer, clientId: provider.clientId, allowedDomains: [domain], enabled: true, ...body } }), ctx);
    expect((await put({ issuer: "http://127.0.0.1:1" })).status).toBe(400);
    expect((await put({ issuer: "http://idp.example.com" })).status).toBe(400);
    expect((await put({ enabled: false, enforced: true })).status).toBe(400);
    // Sem clientSecret, mantém o atual.
    expect((await put({ allowedDomains: [domain, "outro.test"] })).status).toBe(200);

    const other = await ssoOrg();
    const clash = await SSO_PUT(request("/api/organization/sso", { method: "PUT", cookie: other.ownerCookie, body: { issuer: provider.issuer, clientId: provider.clientId, allowedDomains: [domain], enabled: true } }), ctx);
    expect(clash.status).toBe(409);
  });

  it("login de usuário existente, vinculado depois pelo sub", async () => {
    const { add, domain } = await ssoOrg();
    const analyst = await add("analyst", "ana");
    const first = await ssoLogin(`ana@${domain}`, { sub: "sub-ana", email: `ana@${domain}`, email_verified: true, name: "Ana" });
    expect(first.location).toBe("http://localhost/");
    const me = await (await ME(request("/api/auth/me", { cookie: first.cookie }), ctx)).json();
    expect(me.user.id).toBe(analyst.id);
    // Mesmo sub com outro e-mail continua sendo a mesma pessoa.
    const second = await ssoLogin(`ana@${domain}`, { sub: "sub-ana", email: `ana.silva@${domain}` });
    expect((await (await ME(request("/api/auth/me", { cookie: second.cookie }), ctx)).json()).user.id).toBe(analyst.id);
  });

  it("state precisa vir do mesmo navegador e só vale uma vez", async () => {
    const { add, domain } = await ssoOrg();
    await add("viewer", "bia");
    const claims = { sub: "sub-bia", email: `bia@${domain}` };
    const csrf = await ssoLogin(`bia@${domain}`, claims, { dropCookie: true });
    expect(csrf.location).toContain("/login?erro=sso_expired");
    expect(csrf.cookie).toBe("");

    const ok = await ssoLogin(`bia@${domain}`, claims);
    expect(ok.cookie).not.toBe("");
    const { code } = provider.authorize(`${provider.issuer}/authorize?state=${ok.state}`, claims);
    const replay = await CALLBACK(request(`/api/auth/sso/callback?code=${code}&state=${ok.state}`, { cookie: ok.stateCookie }));
    expect(replay.headers.get("location")).toContain("erro=sso_expired");
  });

  it("recusa domínio não permitido, e-mail não verificado, desconhecido sem provisionamento e usuário desativado", async () => {
    const { add, domain, org } = await ssoOrg();
    const unknown = await ssoLogin(`novo@${domain}`, { sub: "sub-novo", email: `novo@${domain}` });
    expect(unknown.location).toContain("erro=sso_not_provisioned");
    const unverified = await ssoLogin(`novo@${domain}`, { sub: "sub-x", email: `novo@${domain}`, email_verified: false });
    expect(unverified.location).toContain("erro=sso_not_provisioned");
    const foreign = await ssoLogin(`novo@${domain}`, { sub: "sub-y", email: "intruso@gmail.com" });
    expect(foreign.location).toContain("erro=sso_not_provisioned");
    expect((await START(request("/api/auth/sso/start?email=alguem@semsso.test"))).headers.get("location")).toContain("erro=sso_unavailable");

    const carla = await add("analyst", "carla");
    await memberRepository(await getDb(), org.id).update(carla.id, { disabled: true });
    expect((await ssoLogin(`carla@${domain}`, { sub: "sub-carla", email: `carla@${domain}` })).location).toContain("erro=sso_not_provisioned");
  });

  it("provisiona no primeiro acesso com o papel configurado", async () => {
    const { domain, org } = await ssoOrg({ jitRole: "viewer" });
    const res = await ssoLogin(`dani@${domain}`, { sub: "sub-dani", email: `Dani@${domain}`, name: "Dani Souza" });
    expect(res.location).toBe("http://localhost/");
    const db = await getDb();
    const [user] = await db.select().from(users).where(eq(users.email, `dani@${domain}`));
    expect(user).toMatchObject({ name: "Dani Souza", passwordHash: null });
    const [m] = await db.select().from(memberships).where(eq(memberships.userId, user.id));
    expect(m).toMatchObject({ organizationId: org.id, role: "viewer" });
  });

  it("SSO obrigatório bloqueia senha de não-Owners e cumpre a política de MFA", async () => {
    const { add, domain, owner, org } = await ssoOrg({ enforced: true });
    await (await getDb()).update(organizations).set({ requireMfa: true }).where(eq(organizations.id, org.id));
    await add("analyst", "edu");
    const pwd = await LOGIN(request("/api/auth/login", { body: { email: `edu@${domain}`, password: TEST_PASSWORD } }));
    expect(pwd.status).toBe(401);
    expect((await pwd.json()).error).toBe(SSO_REQUIRED);
    // Owner mantém a senha para emergências.
    expect((await LOGIN(request("/api/auth/login", { body: { email: owner.email, password: TEST_PASSWORD } }))).status).toBe(200);

    const sso = await ssoLogin(`edu@${domain}`, { sub: "sub-edu", email: `edu@${domain}` });
    const me = await (await ME(request("/api/auth/me", { cookie: sso.cookie }), ctx)).json();
    expect(me.mfaEnrollmentRequired).toBe(false);
    expect((await ASSETS(request("/api/assets", { cookie: sso.cookie }), ctx)).status).toBe(200);
  });
});
