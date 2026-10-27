import { lookup as dnsLookup } from "node:dns/promises";
import { request } from "node:https";
import { isIP, type LookupFunction } from "node:net";
import type { TLSSocket } from "node:tls";
import { analyzeTls, checkDns, systemDns, type DnsLookup, type TlsInfo } from "./checks";
import { isHostAllowed, scannerConfig, type ScannerConfig } from "./config";
import { isPublicAddress } from "./network";
import type { Asset, Finding } from "./types";

/** Achado observado numa execução; a consolidação entre execuções fica no repositório. */
export type Observation = Pick<Finding, "title" | "severity" | "category" | "description" | "evidence" | "recommendation" | "references">;

export type ResolvedAddress = { address: string; family: number };
export type Resolver = (hostname: string) => Promise<ResolvedAddress[]>;
export type ObservedResponse = { status: number; header(name: string): string | undefined; cookies: string[]; tls?: TlsInfo };
export type Fetcher = (url: URL, pinned: ResolvedAddress) => Promise<ObservedResponse>;

export type ScannerMethod = { id: string; name: string; request: string; checks: string[]; exclusions: string[] };
const EXCLUSIONS = ["Exploração", "Teste de autenticação ou autorização", "Varredura de portas", "Crawling", "Análise de corpo ou dados pessoais"];
/** Descrição de cada versão do método, para o relatório citar exatamente o que foi executado. */
export const SCANNER_METHODS: Record<string, ScannerMethod> = {
  "SENTINELA-HTTP-001": { id: "SENTINELA-HTTP-001", name: "Inspeção não intrusiva de metadados HTTP", request: "Uma requisição HTTPS GET à raiz; sem seguir redirecionamentos; timeout de 5 segundos", checks: ["Headers defensivos", "CORS observado", "Atributos de cookies", "Banners Server e X-Powered-By"], exclusions: EXCLUSIONS },
  "SENTINELA-WEB-002": { id: "SENTINELA-WEB-002", name: "Inspeção não intrusiva de HTTP, TLS e DNS", request: "Uma requisição HTTPS GET à raiz (o certificado é lido nessa mesma conexão); sem seguir redirecionamentos; timeout de 5 segundos; consultas DNS públicas ao resolvedor (CAA, MX, SPF, DMARC), sem contato adicional com o alvo", checks: ["Headers defensivos", "CORS observado", "Atributos de cookies", "Banners Server e X-Powered-By", "Confiança e validade do certificado TLS", "CAA, SPF e DMARC"], exclusions: [...EXCLUSIONS, "Enumeração de cifras ou versões de TLS"] }
};
export const SCANNER_METHOD_ID = "SENTINELA-WEB-002";
const USER_AGENT = "Sentinela-Authorized-Assessment/0.3";
const TIMEOUT_MS = 5000;

const systemResolver: Resolver = hostname => dnsLookup(hostname, { all: true, verbatim: true });

export async function validateTarget(raw: string, resolve: Resolver = systemResolver) {
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error("Informe uma URL válida."); }
  if (url.protocol !== "https:") throw new Error("Somente URLs HTTPS são aceitas.");
  if (url.username || url.password || url.port && url.port !== "443") throw new Error("Credenciais embutidas e portas alternativas não são aceitas.");
  if (isIP(url.hostname.replace(/^\[|\]$/g, ""))) throw new Error("Cadastre um hostname DNS, não um IP literal.");
  let addresses: ResolvedAddress[];
  try { addresses = await resolve(url.hostname); } catch { throw new Error("Não foi possível resolver o hostname informado."); }
  if (!addresses.length || addresses.some(({ address }) => !isPublicAddress(address))) throw new Error("O alvo resolve para endereço não público ou não verificável.");
  return { url, addresses };
}

/**
 * Faz uma única requisição GET conectando ao endereço já validado (sem nova
 * resolução DNS, o que impede DNS rebinding). Apenas status e cabeçalhos são
 * lidos; o corpo nunca é consumido e a conexão é encerrada logo após os headers.
 */
export const pinnedFetch: Fetcher = (url, pinned) => new Promise((resolve, reject) => {
  const lookup: LookupFunction = (_hostname, options, callback) => {
    if (options.all) callback(null, [pinned]);
    else callback(null, pinned.address, pinned.family);
  };
  const req = request({
    hostname: url.hostname, port: 443, path: "/", method: "GET", lookup, servername: url.hostname,
    // Certificado inválido vira achado em vez de abortar: só cabeçalhos são lidos e nada sensível é enviado.
    rejectUnauthorized: false,
    headers: { "User-Agent": USER_AGENT, Accept: "*/*" }, maxHeaderSize: 16 * 1024, timeout: TIMEOUT_MS
  }, res => {
    const remote = res.socket?.remoteAddress;
    const raw = res.headers;
    const socket = res.socket as TLSSocket;
    const cert = socket.getPeerCertificate?.();
    const authError = socket.authorizationError as unknown as string | Error | null | undefined;
    const tls: TlsInfo = {
      authorized: socket.authorized, protocol: socket.getProtocol?.() ?? null,
      authorizationError: !authError ? null : typeof authError === "string" ? authError : (authError as Error & { code?: string }).code ?? authError.message,
      validTo: cert?.valid_to ? new Date(cert.valid_to).toISOString() : null,
      issuer: [cert?.issuer?.O, cert?.issuer?.CN].flat().find(Boolean) ?? null
    };
    res.destroy();
    if (remote && remote.replace(/^::ffff:/, "") !== pinned.address.replace(/^::ffff:/, "")) return reject(new Error("A conexão não corresponde ao endereço validado."));
    const setCookie = raw["set-cookie"];
    resolve({
      status: res.statusCode ?? 0,
      header: name => { const value = raw[name.toLowerCase()]; return Array.isArray(value) ? value.join(", ") : value; },
      cookies: Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [],
      tls
    });
  });
  req.on("timeout", () => req.destroy(new Error("Tempo limite excedido ao contatar o alvo.")));
  req.on("error", error => reject(error));
  req.end();
});

const makeFinding = (_asset: Pick<Asset, "url">, title: string, severity: Finding["severity"], category: string, description: string, evidence: string, recommendation: string): Observation => ({ title, severity, category, description, evidence, recommendation, references: ["OWASP Secure Headers Project", "CWE-693"] });

const headerChecks: [string, string, Finding["severity"], string][] = [
  ["content-security-policy", "Política de segurança de conteúdo ausente", "medium", "Defina uma CSP adequada ao inventário de recursos e monitore violações antes do bloqueio."],
  ["strict-transport-security", "HSTS ausente", "low", "Após confirmar HTTPS em todos os subdomínios aplicáveis, habilite HSTS com max-age gradual."],
  ["x-content-type-options", "X-Content-Type-Options ausente", "medium", "Configure X-Content-Type-Options: nosniff."],
  ["referrer-policy", "Referrer-Policy ausente", "medium", "Defina uma política como strict-origin-when-cross-origin conforme os requisitos."],
  ["permissions-policy", "Permissions-Policy ausente", "medium", "Desabilite explicitamente recursos do navegador que a aplicação não utiliza."]
];

function cookieAttributes(cookie: string) {
  return new Set(cookie.split(";").slice(1).map(part => part.split("=")[0].trim().toLowerCase()));
}

/** Converte os metadados observados em achados preliminares. Função pura. */
export function analyzeResponse(asset: Pick<Asset, "url">, response: ObservedResponse): Observation[] {
  const findings: Observation[] = [];
  for (const [header, title, severity, recommendation] of headerChecks) {
    if (response.header(header) === undefined) findings.push(makeFinding(asset, title, severity, "HTTP Headers", `A resposta HTTPS não incluiu ${header}.`, `Header ${header} ausente`, recommendation));
  }
  if (response.header("access-control-allow-origin")?.trim() === "*") findings.push(makeFinding(asset, "CORS permite qualquer origem", "medium", "CORS", "A resposta permite leitura cross-origin por qualquer origem.", "Access-Control-Allow-Origin: *", "Restrinja a lista de origens aos frontends autorizados; não use wildcard em respostas com credenciais."));
  for (const cookie of response.cookies) {
    const attributes = cookieAttributes(cookie);
    const missing = [["secure", "Secure"], ["httponly", "HttpOnly"], ["samesite", "SameSite"]].filter(([key]) => !attributes.has(key)).map(([, label]) => label);
    if (missing.length) findings.push(makeFinding(asset, "Cookie sem atributos de proteção", "low", "Cookies", `Um cookie não declarou todos os atributos esperados (${missing.join(", ")}).`, "Valores e nomes de cookies omitidos; atributos ausentes registrados apenas como categorias.", "Configure Secure, HttpOnly e SameSite conforme o uso do cookie."));
  }
  const server = response.header("server");
  if (server && /\d/.test(server)) findings.push(makeFinding(asset, "Banner de servidor revela versão", "info", "Exposição de informações", "O cabeçalho Server aparenta expor uma versão.", `Server: ${server.slice(0, 80)}`, "Remova versões detalhadas dos banners e mantenha o software atualizado."));
  const poweredBy = response.header("x-powered-by");
  if (poweredBy) findings.push(makeFinding(asset, "Tecnologia anunciada pelo servidor", "info", "Inventário tecnológico", "O cabeçalho X-Powered-By anuncia uma tecnologia; este dado pode não refletir a versão real.", `X-Powered-By: ${poweredBy.slice(0, 80)}`, "Confirme o inventário e evite divulgar detalhes de versão desnecessários."));
  return findings;
}

export type AssessDeps = { config?: ScannerConfig; resolve?: Resolver; fetcher?: Fetcher; dns?: DnsLookup; now?: Date };

/** Falha de rede ao contatar o alvo (tempo limite, conexão recusada): vale tentar de novo mais tarde. */
export class TransientAssessmentError extends Error {}

export async function assess(asset: Pick<Asset, "url">, deps: AssessDeps = {}): Promise<Observation[]> {
  const config = deps.config ?? scannerConfig();
  if (!config.enabled) throw new Error("Scanner desabilitado. Configure o ambiente antes de executar avaliações.");
  const { url, addresses } = await validateTarget(asset.url, deps.resolve);
  if (!isHostAllowed(url.hostname, config)) throw new Error("O hostname não consta na lista de alvos autorizados pelo operador.");
  let response: ObservedResponse;
  try { response = await (deps.fetcher ?? pinnedFetch)(url, addresses[0]); } catch (error) {
    throw new TransientAssessmentError(error instanceof Error ? error.message : "Falha de rede ao contatar o alvo.");
  }
  if (response.status >= 300 && response.status < 400) throw new Error("O alvo respondeu com redirecionamento; o MVP não segue redirects.");
  return [...analyzeResponse(asset, response), ...analyzeTls(response.tls, deps.now), ...await checkDns(url.hostname, deps.dns ?? systemDns())];
}
