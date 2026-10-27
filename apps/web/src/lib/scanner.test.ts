import { describe, expect, it, vi } from "vitest";
import type { DnsLookup } from "./checks";
import { analyzeResponse, assess, validateTarget, type ObservedResponse, type Resolver } from "./scanner";
import type { Asset } from "./types";

const publicResolver: Resolver = async () => [{ address: "93.184.216.34", family: 4 }];
const asset: Pick<Asset, "url"> = { url: "https://app.example.com" };

function response(headers: Record<string, string>, cookies: string[] = [], status = 200): ObservedResponse {
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  return { status, header: name => lower[name.toLowerCase()], cookies };
}

const secureHeaders = {
  "Content-Security-Policy": "default-src 'self'", "Strict-Transport-Security": "max-age=31536000",
  "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=()"
};

describe("validateTarget", () => {
  it("aceita hostname HTTPS que resolve para IP público", async () => {
    const { url, addresses } = await validateTarget("https://app.example.com/path", publicResolver);
    expect(url.hostname).toBe("app.example.com");
    expect(addresses).toHaveLength(1);
  });

  it.each([
    ["http://app.example.com", "Somente URLs HTTPS"],
    ["https://user:pw@app.example.com", "Credenciais embutidas"],
    ["https://app.example.com:8443", "portas alternativas"],
    ["https://93.184.216.34", "IP literal"],
    ["https://[2606:4700::1]", "IP literal"],
    ["not a url", "URL válida"]
  ])("rejeita %s", async (raw, message) => {
    await expect(validateTarget(raw, publicResolver)).rejects.toThrow(message);
  });

  it("rejeita quando qualquer endereço resolvido é privado", async () => {
    const mixed: Resolver = async () => [{ address: "93.184.216.34", family: 4 }, { address: "10.0.0.5", family: 4 }];
    await expect(validateTarget("https://app.example.com", mixed)).rejects.toThrow("não público");
  });

  it("rejeita quando a resolução falha ou não retorna endereços", async () => {
    await expect(validateTarget("https://app.example.com", async () => { throw new Error("ENOTFOUND"); })).rejects.toThrow("resolver");
    await expect(validateTarget("https://app.example.com", async () => [])).rejects.toThrow("não público");
  });
});

describe("analyzeResponse", () => {
  it("não gera achados para resposta bem configurada", () => {
    expect(analyzeResponse(asset, response(secureHeaders, ["sid=x; Path=/; Secure; HttpOnly; SameSite=Lax"]))).toEqual([]);
  });

  it("aponta cada header defensivo ausente", () => {
    const titles = analyzeResponse(asset, response({})).map(f => f.title);
    expect(titles).toEqual(expect.arrayContaining(["Política de segurança de conteúdo ausente", "HSTS ausente", "X-Content-Type-Options ausente", "Referrer-Policy ausente", "Permissions-Policy ausente"]));
  });

  it("detecta CORS wildcard, banners com versão e X-Powered-By", () => {
    const titles = analyzeResponse(asset, response({ ...secureHeaders, "Access-Control-Allow-Origin": "*", Server: "nginx/1.18.0", "X-Powered-By": "Express" })).map(f => f.title);
    expect(titles).toEqual(["CORS permite qualquer origem", "Banner de servidor revela versão", "Tecnologia anunciada pelo servidor"]);
  });

  it("lê atributos de cookie sem se confundir com o valor", () => {
    const [finding] = analyzeResponse(asset, response(secureHeaders, ["token=secure-httponly-samesite; Path=/secure; Domain=example.com"]));
    expect(finding.description).toContain("Secure, HttpOnly, SameSite");
    expect(finding.evidence).not.toContain("token");
  });
});

describe("assess", () => {
  const enabled = { enabled: true, allowedHosts: ["app.example.com"] };

  it("recusa quando o scanner está desabilitado", async () => {
    await expect(assess(asset, { config: { enabled: false, allowedHosts: ["app.example.com"] }, resolve: publicResolver })).rejects.toThrow("desabilitado");
  });

  it("recusa hostname fora da lista do operador sem contatar o alvo", async () => {
    const fetcher = vi.fn();
    await expect(assess(asset, { config: { enabled: true, allowedHosts: ["outro.example.com"] }, resolve: publicResolver, fetcher })).rejects.toThrow("lista de alvos");
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("conecta ao endereço validado (DNS fixado)", async () => {
    const fetcher = vi.fn(async () => response(secureHeaders));
    const dns = { ns: async () => [], caa: async () => [{}], mx: async () => [], txt: async () => [] } as unknown as DnsLookup;
    await assess(asset, { config: enabled, resolve: publicResolver, fetcher, dns });
    expect(fetcher).toHaveBeenCalledWith(expect.any(URL), { address: "93.184.216.34", family: 4 });
  });

  it("junta achados de HTTP, TLS e DNS; DNS consulta o resolvedor, não o alvo", async () => {
    const empty = Object.assign(new Error("none"), { code: "ENODATA" });
    const dns = { ns: vi.fn(async () => ["ns1.example.com"]), caa: vi.fn(async () => { throw empty; }), mx: vi.fn(async () => { throw empty; }), txt: vi.fn(async () => { throw empty; }) } as unknown as DnsLookup;
    const tls = { authorized: false, authorizationError: "CERT_HAS_EXPIRED", protocol: "TLSv1.3", issuer: "CA", validTo: "2026-01-01T00:00:00.000Z" };
    const fetcher = vi.fn(async () => ({ ...response(secureHeaders), tls }));
    const findings = await assess(asset, { config: enabled, resolve: publicResolver, fetcher, dns });
    expect(findings.map(f => f.title)).toEqual(["Certificado TLS não confiável", "Registro CAA ausente"]);
    expect(fetcher).toHaveBeenCalledOnce();
    expect(dns.caa).toHaveBeenCalledWith("app.example.com");
  });

  it("não segue redirecionamentos", async () => {
    await expect(assess(asset, { config: enabled, resolve: publicResolver, fetcher: async () => response({ Location: "https://evil.example" }, [], 302) })).rejects.toThrow("redirecionamento");
  });
});
