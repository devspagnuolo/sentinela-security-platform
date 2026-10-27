import { describe, expect, it } from "vitest";
import { describeMailSettings, mailSettings, notificationEmail } from "./mail";

const env = (vars: Record<string, string>) => vars as unknown as NodeJS.ProcessEnv;

describe("configuração de e-mail", () => {
  it("só liga com URL SMTP e remetente; a senha nunca aparece na descrição", () => {
    expect(mailSettings(env({})).enabled).toBe(false);
    expect(mailSettings(env({ SENTINELA_SMTP_URL: "smtps://u:p@smtp.example.com" })).enabled).toBe(false);
    const full = env({ SENTINELA_SMTP_URL: "smtps://alertas%40ex.com:s3cr3t@smtp.example.com:465", SENTINELA_MAIL_FROM: "Sentinela <alertas@ex.com>" });
    expect(mailSettings(full).enabled).toBe(true);
    const described = describeMailSettings(full);
    expect(described).toEqual({ from: "Sentinela <alertas@ex.com>", server: "smtp.example.com:465" });
    expect(JSON.stringify(described)).not.toContain("s3cr3t");
    expect(describeMailSettings(env({ SENTINELA_SMTP_URL: "smtp://smtp.example.com", SENTINELA_MAIL_FROM: "a@b.c" }))?.server).toBe("smtp.example.com:587");
  });
});

describe("e-mail do aviso", () => {
  const origin = env({ SENTINELA_PUBLIC_ORIGIN: "https://sentinela.example.com" });

  it("texto e HTML com link absoluto e rodapé de descadastro", () => {
    const mail = notificationEmail({ title: "Portal: 1 achado novo de severidade alta", body: "CSP ausente", link: "/achados" }, { email: "ana@ex.com", name: "Ana" }, origin);
    expect(mail).toMatchObject({ to: "ana@ex.com", subject: "[Sentinela] Portal: 1 achado novo de severidade alta" });
    expect(mail.text).toContain("Abrir no Sentinela: https://sentinela.example.com/achados");
    expect(mail.text).toContain("https://sentinela.example.com/conta");
    expect(mail.html).toContain('href="https://sentinela.example.com/achados"');
  });

  it("conteúdo vindo do alvo não vira HTML nem cabeçalho", () => {
    const mail = notificationEmail({ title: "X\r\nBcc: vitima@ex.com", body: "<img src=x onerror=alert(1)>", link: null }, { email: "ana@ex.com", name: "<b>Ana</b>" }, env({}));
    expect(mail.subject).toBe("[Sentinela] X Bcc: vitima@ex.com");
    expect(mail.html).not.toContain("<img");
    expect(mail.html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(mail.html).not.toContain("Abrir no Sentinela");
  });
});
