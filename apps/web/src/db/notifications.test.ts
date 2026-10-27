import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { eq } from "drizzle-orm";
import type { MailMessage } from "@/lib/mail";
import { createDatabase, type Database } from "./client";
import { EMAIL_RETRY_MINUTES, notify, sendPendingEmails } from "./notifications";
import { notifications, organizations, users } from "./schema";
import { memberRepository } from "./users";

let db: Database;
let n = 0;
const MIN = 60_000;

async function org() {
  const [o] = await db.insert(organizations).values({ slug: `mail-${++n}`, name: `Mail ${n}` }).returning();
  const members = memberRepository(db, o.id);
  const make = (role: "owner" | "analyst" | "viewer") => members.create({ email: `${role}-${n}@mail.example`, name: `${role} ${n}`, role, password: "correct-horse-battery-staple" });
  return { orgId: o.id, owner: await make("owner"), analyst: await make("analyst"), viewer: await make("viewer") };
}
const status = async (orgId: string) => Object.fromEntries((await db.select({ userId: notifications.userId, s: notifications.emailStatus }).from(notifications).where(eq(notifications.organizationId, orgId))).map(r => [r.userId, r.s]));
function transport(fail?: string) {
  const sent: MailMessage[] = [];
  return { sent, fn: vi.fn(async (m: MailMessage) => { if (fail) throw new Error(fail); sent.push(m); }) };
}

beforeAll(async () => { db = await createDatabase({ NODE_ENV: "test", SENTINELA_SEED_DEMO: "0" }); });
beforeEach(async () => {
  await db.update(notifications).set({ emailStatus: null });
  vi.stubEnv("SENTINELA_SMTP_URL", "smtp://smtp.example.com:587");
  vi.stubEnv("SENTINELA_MAIL_FROM", "Sentinela <alertas@example.com>");
});
afterEach(() => { vi.unstubAllEnvs(); });

describe("avisos por e-mail", () => {
  it("enfileira para quem quer e recebe o aviso; sem SMTP configurado, nada é enfileirado", async () => {
    const a = await org();
    await db.update(users).set({ emailNotifications: false }).where(eq(users.id, a.analyst.id));
    await notify(db, a.orgId, { audience: "operators" }, { kind: "assessment.attention", title: "Portal: achado alto", body: "CSP ausente", link: "/achados" });
    expect(await status(a.orgId)).toEqual({ [a.owner.id]: "pending", [a.analyst.id]: null });

    const t = transport();
    expect(await sendPendingEmails(db, { transport: t.fn })).toBe(1);
    expect(t.sent).toHaveLength(1);
    expect(t.sent[0]).toMatchObject({ to: a.owner.email, subject: "[Sentinela] Portal: achado alto" });
    expect((await status(a.orgId))[a.owner.id]).toBe("sent");

    vi.unstubAllEnvs();
    const b = await org();
    await notify(db, b.orgId, { audience: "operators" }, { kind: "x", title: "Sem SMTP" });
    expect(Object.values(await status(b.orgId)).every(s => s === null)).toBe(true);
  });

  it("quem desativou a preferência ou a conta depois do aviso não recebe", async () => {
    const a = await org();
    await notify(db, a.orgId, { userIds: [a.owner.id, a.analyst.id] }, { kind: "x", title: "Aviso" });
    await db.update(users).set({ emailNotifications: false }).where(eq(users.id, a.owner.id));
    await db.update(users).set({ disabled: true }).where(eq(users.id, a.analyst.id));
    const t = transport();
    expect(await sendPendingEmails(db, { transport: t.fn })).toBe(0);
    expect(await status(a.orgId)).toEqual({ [a.owner.id]: "skipped", [a.analyst.id]: "skipped" });
  });

  it("falha do SMTP tenta de novo com espera crescente e depois desiste", async () => {
    const a = await org();
    await notify(db, a.orgId, { userIds: [a.viewer.id] }, { kind: "x", title: "Aviso" });
    let clock = Date.now() + 1000;
    const now = () => new Date(clock);
    const t = transport("Connection refused");
    for (const wait of EMAIL_RETRY_MINUTES) {
      expect(await sendPendingEmails(db, { transport: t.fn, now })).toBe(0);
      const [row] = await db.select().from(notifications).where(eq(notifications.userId, a.viewer.id));
      expect(row).toMatchObject({ emailStatus: "pending", emailError: "Connection refused" });
      expect(row.emailNextAttemptAt!.getTime() - clock).toBe(wait * MIN);
      await sendPendingEmails(db, { transport: t.fn, now });
      clock += wait * MIN;
    }
    await sendPendingEmails(db, { transport: t.fn, now });
    const [row] = await db.select().from(notifications).where(eq(notifications.userId, a.viewer.id));
    expect(row).toMatchObject({ emailStatus: "failed", emailAttempts: EMAIL_RETRY_MINUTES.length + 1 });
    expect(t.fn).toHaveBeenCalledTimes(EMAIL_RETRY_MINUTES.length + 1);
  });
});
