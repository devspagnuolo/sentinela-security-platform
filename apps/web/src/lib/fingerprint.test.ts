import { describe, expect, it, vi } from "vitest";
import type { DnsLookup } from "./checks";
import { detectFromDns, detectFromResponse } from "./fingerprint";

const response = (headers: Record<string, string>, cookies: string[] = [], issuer: string | null = null) => ({
  header: (name: string) => Object.entries(headers).find(([k]) => k.toLowerCase() === name.toLowerCase())?.[1],
  cookies,
  tls: issuer ? { authorized: true, authorizationError: null, protocol: "TLSv1.3", validTo: null, issuer } : undefined
});
const names = (list: { category: string; name: string; version: string | null }[]) => list.map(t => `${t.category}:${t.name}${t.version ? `@${t.version}` : ""}`);

describe("detectFromResponse", () => {
  it("lê servidor, framework e versão dos banners", () => {
    expect(names(detectFromResponse(response({ Server: "nginx/1.24.0", "X-Powered-By": "PHP/8.2.12" })))).toEqual(["framework:PHP@8.2.12", "server:nginx@1.24.0"]);
    expect(names(detectFromResponse(response({ Server: "Microsoft-IIS/10.0", "X-Powered-By": "ASP.NET", "X-AspNet-Version": "4.0.30319" })))).toEqual(["framework:ASP.NET@4.0.30319", "server:Microsoft IIS@10.0"]);
    expect(names(detectFromResponse(response({ Server: "Apache-Coyote/1.1" })))).toEqual(["server:Apache Tomcat@1.1"]);
  });

  it("reconhece CDN e hospedagem por cabeçalhos característicos", () => {
    expect(names(detectFromResponse(response({ Server: "cloudflare", "CF-RAY": "8a1-GRU" })))).toEqual(["edge:Cloudflare"]);
    expect(names(detectFromResponse(response({ Via: "1.1 abc.cloudfront.net (CloudFront)", "X-Amz-Cf-Id": "x" })))).toEqual(["edge:Amazon CloudFront"]);
    expect(names(detectFromResponse(response({ Server: "Vercel", "X-Vercel-Id": "gru1::abc" })))).toEqual(["hosting:Vercel"]);
  });

  it("usa só o nome dos cookies, nunca o valor", () => {
    const found = detectFromResponse(response({}, ["PHPSESSID=segredo123; path=/", "wordpress_logged_in_abc=usuario%7Cvalor; HttpOnly", "AWSALB=xyz; Path=/"]));
    expect(names(found)).toEqual(["edge:AWS Elastic Load Balancing", "framework:PHP", "platform:WordPress"]);
    expect(JSON.stringify(found)).not.toMatch(/segredo123|usuario|xyz/);
  });

  it("registra a autoridade certificadora pelo emissor", () => {
    expect(names(detectFromResponse(response({}, [], "Let's Encrypt")))).toEqual(["certificate:Let's Encrypt"]);
    expect(names(detectFromResponse(response({}, [], "CA Interna Ltda")))).toEqual(["certificate:CA Interna Ltda"]);
  });

  it("não inventa nada sem sinais", () => {
    expect(detectFromResponse(response({ "Content-Type": "text/html" }))).toEqual([]);
  });
});

describe("detectFromDns", () => {
  it("identifica provedores de DNS e de e-mail no domínio mais próximo", async () => {
    const empty = Object.assign(new Error("none"), { code: "ENODATA" });
    const dns = {
      ns: vi.fn(async (name: string) => { if (name === "example.com.br") return ["amy.ns.cloudflare.com", "bob.ns.cloudflare.com"]; throw empty; }),
      mx: vi.fn(async (name: string) => { if (name === "example.com.br") return [{ exchange: "example-com-br.mail.protection.outlook.com", priority: 0 }]; throw empty; }),
      caa: vi.fn(), txt: vi.fn()
    } as unknown as DnsLookup;
    expect(names(await detectFromDns("app.example.com.br", dns))).toEqual(["dns:Cloudflare DNS", "email:Microsoft 365"]);
    expect(dns.caa).not.toHaveBeenCalled();
  });

  it("falha do resolvedor não gera inventário nem erro", async () => {
    const dns = { ns: async () => { throw Object.assign(new Error("t"), { code: "ETIMEOUT" }); }, mx: async () => { throw Object.assign(new Error("t"), { code: "ETIMEOUT" }); } } as unknown as DnsLookup;
    expect(await detectFromDns("app.example.com", dns)).toEqual([]);
  });
});
