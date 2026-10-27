import { describe, expect, it } from "vitest";
import { signPayload, verifySignature, webhookUrlError } from "./webhooks";

describe("assinatura dos webhooks", () => {
  const secret = "whsec_teste", body = JSON.stringify({ id: "1", type: "assessment.completed" });
  const now = Date.UTC(2026, 9, 27, 12);
  const t = Math.floor(now / 1000);

  it("HMAC-SHA256 sobre '<t>.<corpo>', conferido pelo destinatário", () => {
    const header = signPayload(secret, body, t);
    expect(header).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
    expect(verifySignature(secret, body, header, now)).toBe(true);
  });

  it("recusa corpo alterado, outro segredo, assinatura antiga e cabeçalho malformado", () => {
    const header = signPayload(secret, body, t);
    expect(verifySignature(secret, `${body} `, header, now)).toBe(false);
    expect(verifySignature("whsec_outro", body, header, now)).toBe(false);
    expect(verifySignature(secret, body, header, now + 301_000)).toBe(false);
    expect(verifySignature(secret, body, "v1=abc", now)).toBe(false);
    expect(verifySignature(secret, body, `t=${t},v1=zz`, now)).toBe(false);
  });
});

describe("URL do webhook", () => {
  it.each([
    ["https://hooks.slack.com/services/x", null],
    ["https://203.0.114.10:8443/hook", null],
    ["http://hooks.example.com", "HTTPS"],
    ["https://user:pass@hooks.example.com", "usuário ou senha"],
    ["https://127.0.0.1/hook", "não é público"],
    ["https://[::1]/hook", "não é público"],
    ["https://10.0.0.5/hook", "não é público"],
    ["https://localhost/hook", "não é público"],
    ["https://coletor.internal/hook", "não é público"],
    ["isto não é url", "URL válida"]
  ])("%s", (url, error) => {
    const result = webhookUrlError(url, {} as NodeJS.ProcessEnv);
    if (error === null) expect(result).toBeNull(); else expect(result).toContain(error);
  });

  it("o operador pode liberar destinos privados", () => {
    expect(webhookUrlError("https://10.0.0.5/hook", { SENTINELA_WEBHOOK_ALLOW_PRIVATE: "1" } as unknown as NodeJS.ProcessEnv)).toBeNull();
  });
});
