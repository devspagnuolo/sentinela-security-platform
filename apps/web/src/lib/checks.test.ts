import { describe, expect, it, vi } from "vitest";
import { ancestors, analyzeTls, checkDns, type DnsLookup, type TlsInfo } from "./checks";

const now = new Date("2026-10-27T12:00:00Z");
const tls = (over: Partial<TlsInfo> = {}): TlsInfo => ({ authorized: true, authorizationError: null, protocol: "TLSv1.3", issuer: "Let's Encrypt", validTo: "2027-01-20T00:00:00.000Z", ...over });

describe("analyzeTls", () => {
  it("sem achado para certificado confiável e longe do vencimento", () => {
    expect(analyzeTls(tls(), now)).toEqual([]);
    expect(analyzeTls(undefined, now)).toEqual([]);
  });

  it.each([
    ["CERT_HAS_EXPIRED", "expirado"],
    ["DEPTH_ZERO_SELF_SIGNED_CERT", "autoassinado"],
    ["ERR_TLS_CERT_ALTNAME_INVALID", "não cobre este hostname"],
    ["UNABLE_TO_VERIFY_LEAF_SIGNATURE", "incompleta"],
    ["ALGO_NOVO", "validação da cadeia falhou"]
  ])("certificado não confiável (%s) é alto", (code, text) => {
    const [finding] = analyzeTls(tls({ authorized: false, authorizationError: code }), now);
    expect(finding).toMatchObject({ title: "Certificado TLS não confiável", severity: "high", category: "TLS" });
    expect(finding.description).toContain(text);
    expect(finding.evidence).toContain(code);
  });

  it("avisa quando faltam menos de 30 dias", () => {
    const [finding] = analyzeTls(tls({ validTo: "2026-11-10T00:00:00.000Z" }), now);
    expect(finding).toMatchObject({ title: "Certificado TLS perto do vencimento", severity: "medium" });
    expect(finding.description).toContain("13 dia");
    expect(finding.evidence).toContain("TLSv1.3");
  });
});

/** DNS falso: mapa nome → registros; nomes ausentes respondem ENOTFOUND. */
function fakeDns(zone: { ns?: Record<string, unknown[]>; caa?: Record<string, unknown[]>; mx?: Record<string, unknown[]>; txt?: Record<string, string[]> }, fail: Partial<Record<keyof DnsLookup, boolean>> = {}): DnsLookup {
  const lookup = (kind: keyof DnsLookup, table: Record<string, unknown[]> = {}) => vi.fn(async (name: string) => {
    if (fail[kind]) throw Object.assign(new Error("timeout"), { code: "ETIMEOUT" });
    if (!(name in table)) throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
    return table[name];
  });
  const txt = Object.fromEntries(Object.entries(zone.txt ?? {}).map(([k, v]) => [k, v.map(x => [x])]));
  return { ns: lookup("ns", zone.ns ?? { "example.com.br": ["ns1.example.com.br"], "com.br": ["a.dns.br"] }), caa: lookup("caa", zone.caa), mx: lookup("mx", zone.mx), txt: lookup("txt", txt) } as unknown as DnsLookup;
}
const titles = async (dns: DnsLookup, host = "app.example.com.br") => (await checkDns(host, dns)).map(f => f.title).sort();

describe("checkDns", () => {
  it("lista o nome e os domínios acima, sem o TLD", () => {
    expect(ancestors("App.Example.com.br.")).toEqual(["app.example.com.br", "example.com.br", "com.br"]);
  });

  it("domínio bem configurado não gera achados (CAA e DMARC herdados do domínio acima)", async () => {
    const dns = fakeDns({
      caa: { "example.com.br": [{ critical: 0, issue: "letsencrypt.org" }] },
      mx: { "example.com.br": [{ exchange: "mx.example.com.br", priority: 10 }] },
      txt: { "example.com.br": ["v=spf1 include:_spf.google.com ~all"], "_dmarc.example.com.br": ["v=DMARC1; p=reject; rua=mailto:d@example.com.br"] }
    });
    expect(await titles(dns)).toEqual([]);
  });

  it("aponta CAA, SPF e DMARC ausentes", async () => {
    const dns = fakeDns({ mx: { "example.com.br": [{ exchange: "mx", priority: 10 }] }, txt: { "example.com.br": ["google-site-verification=x"] } });
    expect(await titles(dns)).toEqual(["DMARC ausente", "Registro CAA ausente", "SPF ausente no domínio de e-mail"]);
  });

  it("DMARC em p=none é informativo; sem MX não há verificação de e-mail", async () => {
    const mail = fakeDns({ caa: { "app.example.com.br": [{}] }, mx: { "example.com.br": [{}] }, txt: { "example.com.br": ["v=spf1 -all"], "_dmarc.example.com.br": ["v=DMARC1; p=none"] } });
    expect(await titles(mail)).toEqual(["DMARC sem política de bloqueio"]);
    expect(await titles(fakeDns({ caa: { "example.com.br": [{}] } }))).toEqual([]);
  });

  it("resolvedor que só responde A/AAAA (sem NS em nenhum nível) não gera achados", async () => {
    expect(await titles(fakeDns({ ns: {} }))).toEqual([]);
    expect(await titles(fakeDns({}, { ns: true }))).toEqual([]);
  });

  it("erro do resolvedor omite a verificação em vez de acusar ausência", async () => {
    expect(await titles(fakeDns({}, { caa: true, mx: true }))).toEqual([]);
    expect(await titles(fakeDns({ mx: { "example.com.br": [{}] } }, { caa: true, txt: true }))).toEqual([]);
  });
});
