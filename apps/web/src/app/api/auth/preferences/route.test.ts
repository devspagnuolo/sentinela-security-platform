import { afterEach, describe, expect, it, vi } from "vitest";
import { eq } from "drizzle-orm";
import { request, signIn } from "@/test/auth";

const sent: { to: string }[] = [];
vi.mock("@/lib/mail", async importOriginal => ({
  ...(await importOriginal<typeof import("@/lib/mail")>()),
  smtpTransport: () => async (m: { to: string }) => { if (m.to.startsWith("owner")) throw new Error("535 Authentication failed"); sent.push(m); }
}));

const { PUT } = await import("./route");
const { POST: EMAIL_TEST } = await import("../../integrations/email-test/route");
const { getDb } = await import("@/db/client");
const { users } = await import("@/db/schema");
const ctx = {} as never;

afterEach(() => { vi.unstubAllEnvs(); });

describe("preferências e e-mail de teste", () => {
  it("cada pessoa liga e desliga os próprios e-mails", async () => {
    const { cookie, user } = await signIn("viewer");
    expect((await PUT(request("/api/auth/preferences", { cookie, method: "PUT", body: { emailNotifications: "sim" } }), ctx)).status).toBe(400);
    expect((await PUT(request("/api/auth/preferences", { cookie, method: "PUT", body: { emailNotifications: false } }), ctx)).status).toBe(200);
    const [row] = await (await getDb()).select({ e: users.emailNotifications }).from(users).where(eq(users.id, user.id));
    expect(row.e).toBe(false);
    expect((await PUT(request("/api/auth/preferences", { method: "PUT", body: { emailNotifications: true } }), ctx)).status).toBe(401);
  });

  it("teste de e-mail: só gestão, exige SMTP configurado e mostra o erro do servidor", async () => {
    const analyst = await signIn("analyst");
    const admin = await signIn("admin", analyst.organizationId);
    const owner = await signIn("owner", analyst.organizationId);
    expect((await EMAIL_TEST(request("/api/integrations/email-test", { cookie: analyst.cookie, body: {} }), ctx)).status).toBe(403);
    expect((await EMAIL_TEST(request("/api/integrations/email-test", { cookie: admin.cookie, body: {} }), ctx)).status).toBe(409);
    vi.stubEnv("SENTINELA_SMTP_URL", "smtp://smtp.example.com");
    vi.stubEnv("SENTINELA_MAIL_FROM", "alertas@example.com");
    expect(await (await EMAIL_TEST(request("/api/integrations/email-test", { cookie: admin.cookie, body: {} }), ctx)).json()).toEqual({ ok: true, to: admin.user.email });
    expect(sent.at(-1)?.to).toBe(admin.user.email);
    const failed = await EMAIL_TEST(request("/api/integrations/email-test", { cookie: owner.cookie, body: {} }), ctx);
    expect(failed.status).toBe(502);
    expect((await failed.json()).error).toContain("535 Authentication failed");
  });
});
