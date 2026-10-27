import { eq } from "drizzle-orm";
import { beforeAll, describe, expect, it } from "vitest";
import { createDatabase, type Database } from "@/db/client";
import { tenantRepository } from "@/db/repository";
import { organizations, sessions, users } from "@/db/schema";
import { memberRepository } from "@/db/users";
import { INVALID_CREDENTIALS, LOCKOUT_MS, login, MAX_FAILED_LOGINS } from "./login";
import { createSession, revokeSession, revokeUserSessions, SESSION_IDLE_MS, SESSION_TTL_MS, validateSession } from "./session";

let db: Database;
let orgId: string;
const password = "correct-horse-battery-staple";
let n = 0;
const newUser = async (role: "owner" | "viewer" = "viewer") => memberRepository(db, orgId).create({ email: `u${++n}@example.com`, name: "Teste", role, password });

beforeAll(async () => {
  db = await createDatabase({ NODE_ENV: "test", SENTINELA_SEED_DEMO: "0" });
  [{ id: orgId }] = await db.insert(organizations).values({ slug: "auth", name: "Auth" }).returning();
});

describe("sessões", () => {
  it("guarda apenas o hash do token e valida usuário, papel e organização", async () => {
    const user = await newUser("owner");
    const { token } = await createSession(db, { userId: user.id, organizationId: orgId });
    const stored = await db.select().from(sessions).where(eq(sessions.userId, user.id));
    expect(stored[0].id).not.toContain(token);
    expect(await validateSession(db, token)).toMatchObject({ organizationId: orgId, role: "owner", user: { id: user.id } });
  });

  it("expira por tempo absoluto e por ociosidade", async () => {
    const user = await newUser();
    const start = new Date("2026-01-01T00:00:00Z");
    const a = await createSession(db, { userId: user.id, organizationId: orgId }, start);
    expect(await validateSession(db, a.token, new Date(start.getTime() + SESSION_TTL_MS + 1))).toBeNull();
    const b = await createSession(db, { userId: user.id, organizationId: orgId }, start);
    expect(await validateSession(db, b.token, new Date(start.getTime() + SESSION_IDLE_MS + 1))).toBeNull();
    expect(await validateSession(db, "token-inexistente")).toBeNull();
    expect(await validateSession(db, undefined)).toBeNull();
  });

  it("invalida sessões de usuário desativado, revogado ou removido da organização", async () => {
    const user = await newUser();
    const s1 = await createSession(db, { userId: user.id, organizationId: orgId });
    await revokeSession(db, s1.token);
    expect(await validateSession(db, s1.token)).toBeNull();
    const s2 = await createSession(db, { userId: user.id, organizationId: orgId });
    await db.update(users).set({ disabled: true }).where(eq(users.id, user.id));
    expect(await validateSession(db, s2.token)).toBeNull();
    const other = await newUser();
    const [{ id: otherOrg }] = await db.insert(organizations).values({ slug: "outra", name: "Outra" }).returning();
    const s3 = await createSession(db, { userId: other.id, organizationId: otherOrg });
    expect(await validateSession(db, s3.token)).toBeNull();
    const s4 = await createSession(db, { userId: other.id, organizationId: orgId });
    await revokeUserSessions(db, other.id);
    expect(await validateSession(db, s4.token)).toBeNull();
  });
});

describe("login", () => {
  it("autentica, cria sessão e audita", async () => {
    const user = await newUser();
    const result = await login(db, user.email.toUpperCase(), password, { ip: "203.0.113.9" });
    expect(result.ok).toBe(true);
    if (result.ok) expect(await validateSession(db, result.token)).not.toBeNull();
    const [entry] = await tenantRepository(db, orgId).listAudit(1);
    expect(entry).toMatchObject({ action: "auth.login_succeeded", targetId: user.id, actorUserId: user.id });
  });

  it("responde igual para e-mail inexistente e senha errada", async () => {
    const user = await newUser();
    expect(await login(db, "ninguem@example.com", password)).toEqual({ ok: false, error: INVALID_CREDENTIALS });
    expect(await login(db, user.email, "senha errada qualquer")).toEqual({ ok: false, error: INVALID_CREDENTIALS });
  });

  it(`bloqueia a conta após ${MAX_FAILED_LOGINS} falhas, mesmo com a senha certa, e libera após o prazo`, async () => {
    const user = await newUser();
    const now = new Date();
    for (let i = 0; i < MAX_FAILED_LOGINS; i++) await login(db, user.email, "senha errada qualquer", {}, now);
    expect((await login(db, user.email, password, {}, now)).ok).toBe(false);
    const actions = (await tenantRepository(db, orgId).listAudit(3)).map(e => e.action);
    expect(actions).toContain("auth.account_locked");
    expect((await login(db, user.email, password, {}, new Date(now.getTime() + LOCKOUT_MS + 1000))).ok).toBe(true);
  });

  it("recusa conta desativada", async () => {
    const user = await newUser();
    await db.update(users).set({ disabled: true }).where(eq(users.id, user.id));
    expect((await login(db, user.email, password)).ok).toBe(false);
  });
});
