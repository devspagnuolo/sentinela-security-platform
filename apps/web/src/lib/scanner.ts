import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { randomUUID } from "node:crypto";
import type { Asset, Finding } from "./types";

function isForbiddenIPv4(ip: string) {
  const [a,b] = ip.split(".").map(Number);
  return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}
function isForbiddenIPv6(ip: string) {
  const s = ip.toLowerCase();
  return s === "::" || s === "::1" || s.startsWith("fc") || s.startsWith("fd") || s.startsWith("fe8") || s.startsWith("fe9") || s.startsWith("fea") || s.startsWith("feb") || s.startsWith("ff") || s.startsWith("::ffff:");
}
export async function validateTarget(raw: string) {
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error("Informe uma URL válida."); }
  if (url.protocol !== "https:") throw new Error("Somente URLs HTTPS são aceitas.");
  if (url.username || url.password || url.port && url.port !== "443") throw new Error("Credenciais embutidas e portas alternativas não são aceitas.");
  if (isIP(url.hostname)) throw new Error("Cadastre um hostname DNS, não um IP literal.");
  const results = await lookup(url.hostname, { all: true, verbatim: true });
  if (!results.length || results.some(({address, family}) => family === 4 ? isForbiddenIPv4(address) : isForbiddenIPv6(address))) throw new Error("O alvo resolve para endereço não público ou não verificável.");
  return url;
}
const makeFinding = (asset: Asset, title: string, severity: Finding["severity"], category: string, description: string, evidence: string, recommendation: string): Finding => ({ id: randomUUID(), assetId: asset.id, title, severity, category, description, evidence, recommendation, references: ["OWASP Secure Headers Project", "CWE-693"], discoveredAt: new Date().toISOString() });

export async function assess(asset: Asset): Promise<Finding[]> {
  const url = await validateTarget(asset.url);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(url, { method: "GET", redirect: "manual", signal: controller.signal, headers: { "User-Agent": "Sentinela-Authorized-Assessment/0.1" }, cache: "no-store" });
    if (response.status >= 300 && response.status < 400) throw new Error("O alvo respondeu com redirecionamento; o MVP não segue redirects.");
    const findings: Finding[] = [];
    const headers = response.headers;
    const checks: [string,string,string][] = [
      ["content-security-policy", "Política de segurança de conteúdo ausente", "Defina uma CSP adequada ao inventário de recursos e monitore violações antes do bloqueio."],
      ["strict-transport-security", "HSTS ausente", "Após confirmar HTTPS em todos os subdomínios aplicáveis, habilite HSTS com max-age gradual."],
      ["x-content-type-options", "X-Content-Type-Options ausente", "Configure X-Content-Type-Options: nosniff."],
      ["referrer-policy", "Referrer-Policy ausente", "Defina uma política como strict-origin-when-cross-origin conforme os requisitos."],
      ["permissions-policy", "Permissions-Policy ausente", "Desabilite explicitamente recursos do navegador que a aplicação não utiliza."]
    ];
    for (const [header,title,recommendation] of checks) if (!headers.has(header)) findings.push(makeFinding(asset,title,header === "strict-transport-security" ? "low" : "medium","HTTP Headers",`A resposta HTTPS não incluiu ${header}.`,`Header ${header} ausente`,recommendation));
    const acao = headers.get("access-control-allow-origin");
    if (acao === "*") findings.push(makeFinding(asset,"CORS permite qualquer origem","medium","CORS","A resposta permite leitura cross-origin por qualquer origem.","Access-Control-Allow-Origin: *","Restrinja a lista de origens aos frontends autorizados; não use wildcard em respostas com credenciais."));
    const cookies = headers.getSetCookie?.() ?? (headers.get("set-cookie") ? [headers.get("set-cookie")!] : []);
    for (const cookie of cookies) {
      const lower = cookie.toLowerCase();
      const missing = [!lower.includes("; secure") && "Secure", !lower.includes("; httponly") && "HttpOnly", !lower.includes("samesite=") && "SameSite"].filter(Boolean);
      if (missing.length) findings.push(makeFinding(asset,"Cookie sem atributos de proteção","low","Cookies",`Um cookie não declarou todos os atributos esperados (${missing.join(", ")}).`,"Valores e nomes de cookies omitidos; atributos ausentes registrados apenas como categorias.","Configure Secure, HttpOnly e SameSite conforme o uso do cookie."));
    }
    const server = headers.get("server");
    if (server && /\d/.test(server)) findings.push(makeFinding(asset,"Banner de servidor revela versão","info","Exposição de informações","O cabeçalho Server aparenta expor uma versão.",`Server: ${server.slice(0,80)}`,"Remova versões detalhadas dos banners e mantenha o software atualizado."));
    await response.body?.cancel();
    return findings;
  } finally { clearTimeout(timer); }
}
