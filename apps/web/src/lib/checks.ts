import { Resolver as DnsResolver } from "node:dns/promises";
import type { CaaRecord, MxRecord } from "node:dns";
import type { Observation } from "./scanner";

const DAY_MS = 86_400_000;
export const CERT_EXPIRY_WARNING_DAYS = 30;

// ---- TLS ---------------------------------------------------------------------------

/** O que foi observado do certificado na mesma conexão da requisição HTTPS (nenhuma conexão extra). */
export type TlsInfo = { authorized: boolean; authorizationError: string | null; protocol: string | null; validTo: string | null; issuer: string | null };

const TLS_ERRORS: Record<string, string> = {
  CERT_HAS_EXPIRED: "o certificado está expirado",
  CERT_NOT_YET_VALID: "o certificado ainda não é válido",
  DEPTH_ZERO_SELF_SIGNED_CERT: "o certificado é autoassinado",
  SELF_SIGNED_CERT_IN_CHAIN: "a cadeia contém um certificado autoassinado",
  ERR_TLS_CERT_ALTNAME_INVALID: "o certificado não cobre este hostname",
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: "a cadeia de certificação está incompleta",
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: "a cadeia de certificação está incompleta ou usa uma CA não reconhecida"
};

const tlsFinding = (title: string, severity: Observation["severity"], description: string, evidence: string, recommendation: string): Observation =>
  ({ title, severity, category: "TLS", description, evidence, recommendation, references: ["OWASP Transport Layer Security Cheat Sheet", "CWE-295"] });

/** Converte o certificado observado em achados. Função pura. */
export function analyzeTls(tls: TlsInfo | undefined, now = new Date()): Observation[] {
  if (!tls) return [];
  const context = [tls.protocol && `protocolo ${tls.protocol}`, tls.issuer && `emissor ${tls.issuer}`, tls.validTo && `válido até ${tls.validTo.slice(0, 10)}`].filter(Boolean).join(", ");
  if (!tls.authorized) {
    const reason = TLS_ERRORS[tls.authorizationError ?? ""] ?? "a validação da cadeia falhou";
    return [tlsFinding("Certificado TLS não confiável", "high", `Navegadores exibirão alerta de segurança: ${reason}. Usuários tendem a ignorar o alerta, o que facilita interceptação.`,
      `Erro de validação ${tls.authorizationError ?? "desconhecido"}${context ? `; ${context}` : ""}`,
      "Emita um certificado de uma CA pública que cubra o hostname, sirva a cadeia intermediária completa e automatize a renovação (ex.: ACME).")];
  }
  if (tls.validTo) {
    const days = Math.floor((new Date(tls.validTo).getTime() - now.getTime()) / DAY_MS);
    if (days < CERT_EXPIRY_WARNING_DAYS) return [tlsFinding("Certificado TLS perto do vencimento", "medium", `O certificado vence em ${Math.max(days, 0)} dia(s); se não for renovado a tempo, o acesso será bloqueado pelos navegadores.`,
      context, "Confirme que a renovação automática está funcionando e monitore o vencimento dos certificados.")];
  }
  return [];
}

// ---- DNS ---------------------------------------------------------------------------

/** Consultas DNS usadas pelas verificações (injetáveis nos testes). Vão ao resolvedor, nunca ao alvo. */
export type DnsLookup = { ns(name: string): Promise<string[]>; caa(name: string): Promise<CaaRecord[]>; txt(name: string): Promise<string[][]>; mx(name: string): Promise<MxRecord[]> };

export function systemDns(timeout = 3000): DnsLookup {
  const resolver = new DnsResolver({ timeout, tries: 2 });
  return { ns: name => resolver.resolveNs(name), caa: name => resolver.resolveCaa(name), txt: name => resolver.resolveTxt(name), mx: name => resolver.resolveMx(name) };
}

/** Nome inexistente ou sem registros do tipo = vazio; demais erros (tempo limite, SERVFAIL) interrompem a verificação. */
async function records<T>(query: Promise<T[]>): Promise<T[]> {
  try { return await query; } catch (error) {
    const code = (error as { code?: string }).code;
    if (code === "ENODATA" || code === "ENOTFOUND") return [];
    throw error;
  }
}

/** app.example.com.br → app.example.com.br, example.com.br, com.br (o TLD sozinho fica de fora). */
export function ancestors(hostname: string) {
  const labels = hostname.toLowerCase().replace(/\.$/, "").split(".");
  return labels.slice(0, -1).map((_, i) => labels.slice(i).join("."));
}

const dnsFinding = (title: string, severity: Observation["severity"], description: string, evidence: string, recommendation: string, references: string[]): Observation =>
  ({ title, severity, category: "DNS", description, evidence, recommendation, references });

const txtStartingWith = (rows: string[][], prefix: string) => rows.map(parts => parts.join("")).find(value => value.trim().toLowerCase().startsWith(prefix));

/** CAA: vale o registro do próprio nome ou do ancestral mais próximo (RFC 8659). */
async function checkCaa(hostname: string, dns: DnsLookup): Promise<Observation[]> {
  for (const name of ancestors(hostname)) if ((await records(dns.caa(name))).length) return [];
  return [dnsFinding("Registro CAA ausente", "info", "Sem CAA, qualquer autoridade certificadora pode emitir certificados para o domínio.",
    `Nenhum registro CAA em ${hostname} nem nos domínios acima.`, "Publique registros CAA autorizando apenas as CAs usadas pela organização.", ["RFC 8659"])];
}

/** SPF e DMARC no domínio de e-mail mais próximo (primeiro ancestral com MX). Sem MX, não há o que verificar. */
async function checkMail(hostname: string, dns: DnsLookup): Promise<Observation[]> {
  const chain = ancestors(hostname);
  let mailDomain: string | undefined;
  for (const name of chain) if ((await records(dns.mx(name))).length) { mailDomain = name; break; }
  if (!mailDomain) return [];
  const findings: Observation[] = [];
  if (!txtStartingWith(await records(dns.txt(mailDomain)), "v=spf1")) findings.push(dnsFinding("SPF ausente no domínio de e-mail", "low",
    "O domínio recebe e-mail (MX) mas não publica SPF; servidores de destino não conseguem verificar quem pode enviar em seu nome.",
    `${mailDomain} tem MX e nenhum TXT "v=spf1".`, "Publique um registro SPF listando os remetentes legítimos e terminando em ~all ou -all.", ["RFC 7208", "CWE-290"]));
  let dmarc: string | undefined;
  for (const name of chain.slice(chain.indexOf(mailDomain))) {
    dmarc = txtStartingWith(await records(dns.txt(`_dmarc.${name}`)), "v=dmarc1");
    if (dmarc) break;
  }
  if (!dmarc) findings.push(dnsFinding("DMARC ausente", "low", "Sem DMARC, mensagens que falsificam o domínio não são rejeitadas de forma consistente e o dono do domínio não recebe relatórios.",
    `Nenhum TXT "v=DMARC1" em _dmarc.${mailDomain} nem nos domínios acima.`, "Publique DMARC começando com p=none e relatórios (rua), e evolua para quarantine/reject.", ["RFC 7489"]));
  else if (/;\s*p\s*=\s*none/i.test(dmarc)) findings.push(dnsFinding("DMARC sem política de bloqueio", "info", "A política p=none apenas monitora; mensagens falsificadas continuam sendo entregues.",
    dmarc.slice(0, 200), "Depois de analisar os relatórios, evolua para p=quarantine ou p=reject.", ["RFC 7489"]));
  return findings;
}

/**
 * Verificações DNS passivas. Uma verificação que falha por erro do resolvedor é omitida (sem falso positivo).
 * Antes, confere se o resolvedor responde registros além de A/AAAA: todo domínio registrado tem NS no
 * apex da zona. Resolvedores filtrados (proxies, redes restritas) devolvem vazio para tudo e gerariam
 * "ausente" falso; nesse caso nenhuma verificação DNS é feita.
 */
export async function checkDns(hostname: string, dns: DnsLookup): Promise<Observation[]> {
  try {
    let answered = false;
    for (const name of ancestors(hostname)) if ((await records(dns.ns(name))).length) { answered = true; break; }
    if (!answered) return [];
  } catch { return []; }
  const results = await Promise.allSettled([checkCaa(hostname, dns), checkMail(hostname, dns)]);
  return results.flatMap(r => r.status === "fulfilled" ? r.value : []);
}
