import { describe, expect, it } from "vitest";
import { getDb } from "@/db/client";
import { mfaChallenges } from "@/db/schema";
import { timeStep, totpAt } from "@/lib/auth/totp";
import { request, signIn, TEST_PASSWORD } from "@/test/auth";
import { GET as ASSETS } from "../assets/route";
import { PATCH as ORG } from "../organization/route";
import { PATCH as USER } from "../users/[id]/route";
import { POST as LOGIN } from "./login/route";
import { GET as ME } from "./me/route";
import { POST as DISABLE } from "./mfa/disable/route";
import { POST as ENABLE } from "./mfa/enable/route";
import { POST as RECOVERY } from "./mfa/recovery-codes/route";
import { POST as SETUP } from "./mfa/setup/route";
import { POST as VERIFY } from "./mfa/verify/route";

const ctx = {} as never;
const cookieFrom = (res: Response) => res.headers.get("set-cookie")?.split(";")[0] ?? "";
const code = (secret: string, offset = 0) => totpAt(secret, timeStep() + offset);

/** Usuário com MFA ativo; devolve segredo e códigos de recuperação. */
async function enrolled(role: "owner" | "admin" | "analyst" | "viewer" = "analyst", organizationId?: string) {
  const s = await signIn(role, organizationId);
  const setup = await (await SETUP(request("/api/auth/mfa/setup", { cookie: s.cookie, body: {} }), ctx)).json();
  const res = await ENABLE(request("/api/auth/mfa/enable", { cookie: s.cookie, body: { code: code(setup.secret) } }), ctx);
  expect(res.status).toBe(200);
  return { ...s, secret: setup.secret as string, recoveryCodes: (await res.json()).recoveryCodes as string[] };
}
const login = async (email: string) => (await LOGIN(request("/api/auth/login", { body: { email, password: TEST_PASSWORD } }))).json();
const verify = (challenge: string, c: string) => VERIFY(request("/api/auth/mfa/verify", { body: { challenge, code: c } }));

describe("MFA", () => {
  it("cadastro devolve QR code e só ativa com código válido", async () => {
    const { cookie } = await signIn("viewer");
    const setup = await (await SETUP(request("/api/auth/mfa/setup", { cookie, body: {} }), ctx)).json();
    expect(setup.qrSvg).toContain("<svg");
    expect(setup.uri).toContain("otpauth://totp/");
    expect((await ENABLE(request("/api/auth/mfa/enable", { cookie, body: { code: "000000" } }), ctx)).status).toBe(400);
    const ok = await ENABLE(request("/api/auth/mfa/enable", { cookie, body: { code: code(setup.secret) } }), ctx);
    expect((await ok.json()).recoveryCodes).toHaveLength(10);
    expect((await (await ME(request("/api/auth/me", { cookie }), ctx)).json()).mfaEnabled).toBe(true);
  });

  it("login passa a exigir o segundo fator e não aceita reuso do mesmo código", async () => {
    const { user, secret } = await enrolled();
    const first = await login(user.email);
    expect(first).toEqual({ mfaRequired: true, challenge: expect.any(String) });
    expect((await verify(first.challenge, code(secret))).status).toBe(401);
    const res = await verify(first.challenge, code(secret, 1));
    expect(res.status).toBe(200);
    expect((await ME(request("/api/auth/me", { cookie: cookieFrom(res) }), ctx)).status).toBe(200);
    expect((await verify(first.challenge, code(secret, 1))).status).toBe(401);
  });

  it("código de recuperação funciona uma única vez", async () => {
    const { user, recoveryCodes } = await enrolled();
    const a = await login(user.email);
    expect((await verify(a.challenge, recoveryCodes[0].toUpperCase())).status).toBe(200);
    const b = await login(user.email);
    expect((await verify(b.challenge, recoveryCodes[0])).status).toBe(401);
  });

  it("erros no segundo fator bloqueiam a conta e o desafio expira", async () => {
    const { user, secret } = await enrolled();
    const { challenge } = await login(user.email);
    for (let i = 0; i < 5; i++) await verify(challenge, "000000");
    const after = await login(user.email);
    expect(after.error).toBeDefined();
    const other = await enrolled();
    const { challenge: c2 } = await login(other.user.email);
    await (await getDb()).update(mfaChallenges).set({ expiresAt: new Date(Date.now() - 1000) });
    expect((await verify(c2, code(other.secret, 1))).status).toBe(401);
    expect(secret).toBeTruthy();
  });

  it("desativar e regenerar códigos exigem a senha", async () => {
    const { cookie } = await enrolled();
    expect((await RECOVERY(request("/api/auth/mfa/recovery-codes", { cookie, body: { password: "errada" } }), ctx)).status).toBe(400);
    expect((await (await RECOVERY(request("/api/auth/mfa/recovery-codes", { cookie, body: { password: TEST_PASSWORD } }), ctx)).json()).recoveryCodes).toHaveLength(10);
    expect((await DISABLE(request("/api/auth/mfa/disable", { cookie, body: { password: "errada" } }), ctx)).status).toBe(400);
    expect((await DISABLE(request("/api/auth/mfa/disable", { cookie, body: { password: TEST_PASSWORD } }), ctx)).status).toBe(200);
    expect((await (await ME(request("/api/auth/me", { cookie }), ctx)).json()).mfaEnabled).toBe(false);
  });

  it("política da organização: só Owner com MFA ativa; quem não cadastrou fica restrito à própria conta", async () => {
    const plainOwner = await signIn("owner");
    expect((await ORG(request("/api/organization", { cookie: plainOwner.cookie, body: { requireMfa: true }, method: "PATCH" }), ctx)).status).toBe(409);
    const owner = await enrolled("owner");
    const admin = await signIn("admin", owner.organizationId);
    expect((await ORG(request("/api/organization", { cookie: admin.cookie, body: { requireMfa: true }, method: "PATCH" }), ctx)).status).toBe(403);
    expect((await ORG(request("/api/organization", { cookie: owner.cookie, body: { requireMfa: true }, method: "PATCH" }), ctx)).status).toBe(200);
    const viewer = await signIn("viewer", owner.organizationId);
    const blocked = await ASSETS(request("/api/assets", { cookie: viewer.cookie }), ctx);
    expect(blocked.status).toBe(403);
    expect((await blocked.json()).code).toBe("mfa_enrollment_required");
    expect((await (await ME(request("/api/auth/me", { cookie: viewer.cookie }), ctx)).json()).mfaEnrollmentRequired).toBe(true);
    expect((await ASSETS(request("/api/assets", { cookie: owner.cookie }), ctx)).status).toBe(200);
  });

  it("Admin reseta o MFA de um Analista, encerrando as sessões dele", async () => {
    const owner = await signIn("owner");
    const analyst = await enrolled("analyst", owner.organizationId);
    const res = await USER(request(`/api/users/${analyst.user.id}`, { cookie: owner.cookie, body: { resetMfa: true }, method: "PATCH" }), { params: Promise.resolve({ id: analyst.user.id }) });
    expect((await res.json()).mfaEnabled).toBe(false);
    expect((await ME(request("/api/auth/me", { cookie: analyst.cookie }), ctx)).status).toBe(401);
    expect((await login(analyst.user.email)).mfaRequired).toBeUndefined();
  });
});
