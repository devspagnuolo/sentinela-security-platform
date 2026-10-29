import type { MxRecord } from "node:dns";
import { ancestors, records, type DnsLookup } from "./checks";
import type { TechnologyCategory } from "./labels";
import type { ObservedResponse } from "./scanner";

/**
 * Inventário passivo: identifica tecnologias a partir do que a avaliação já
 * observou (cabeçalhos da única requisição, certificado da mesma conexão e
 * consultas DNS ao resolvedor). Nenhuma requisição extra ao alvo, nenhum
 * caminho conhecido testado e nenhum corpo lido. Nomes de cookies servem só
 * para a detecção; valores nunca são lidos nem gravados.
 */

export type Technology = { name: string; category: TechnologyCategory; version: string | null; evidence: string };

type Rule = { name: string; category: TechnologyCategory; pattern: RegExp };

// Cabeçalho Server (o primeiro grupo de captura, se houver, é a versão).
const SERVER_RULES: Rule[] = [
  { name: "nginx", category: "server", pattern: /\bnginx(?:\/([\d.]+))?/i },
  { name: "OpenResty", category: "server", pattern: /\bopenresty(?:\/([\d.]+))?/i },
  { name: "Apache HTTP Server", category: "server", pattern: /\bApache(?:\/([\d.]+))?(?![-\w])/i },
  { name: "Microsoft IIS", category: "server", pattern: /\bMicrosoft-IIS(?:\/([\d.]+))?/i },
  { name: "LiteSpeed", category: "server", pattern: /\bLiteSpeed/i },
  { name: "Caddy", category: "server", pattern: /\bCaddy/i },
  { name: "Envoy", category: "server", pattern: /\benvoy/i },
  { name: "Kestrel", category: "server", pattern: /\bKestrel/i },
  { name: "Jetty", category: "server", pattern: /\bJetty(?:\(([\d.]+)[^)]*\))?/i },
  { name: "Apache Tomcat", category: "server", pattern: /\bApache-Coyote(?:\/([\d.]+))?/i },
  { name: "Gunicorn", category: "server", pattern: /\bgunicorn(?:\/([\d.]+))?/i },
  { name: "Cloudflare", category: "edge", pattern: /^cloudflare$/i },
  { name: "Amazon S3", category: "hosting", pattern: /^AmazonS3$/i },
  { name: "Google Frontend", category: "hosting", pattern: /^(gws|Google Frontend|ESF)$/i },
  { name: "Vercel", category: "hosting", pattern: /^Vercel$/i },
  { name: "Netlify", category: "hosting", pattern: /^Netlify$/i },
  { name: "GitHub Pages", category: "hosting", pattern: /^GitHub\.com$/i }
];

const POWERED_BY_RULES: Rule[] = [
  { name: "PHP", category: "framework", pattern: /\bPHP(?:\/([\d.]+))?/i },
  { name: "ASP.NET", category: "framework", pattern: /\bASP\.NET/i },
  { name: "Express", category: "framework", pattern: /\bExpress\b/i },
  { name: "Next.js", category: "framework", pattern: /\bNext\.js(?:\s+([\d.]+))?/i },
  { name: "Java Servlet", category: "framework", pattern: /\bServlet(?:\/([\d.]+))?/i },
  { name: "Phusion Passenger", category: "server", pattern: /\bPhusion Passenger(?:\s+([\d.]+))?/i },
  { name: "WordPress", category: "platform", pattern: /\bWordPress/i },
  { name: "Wix", category: "platform", pattern: /\bWix/i }
];

// Presença de um cabeçalho característico.
const HEADER_RULES: { header: string; name: string; category: TechnologyCategory; version?: boolean }[] = [
  { header: "cf-ray", name: "Cloudflare", category: "edge" },
  { header: "x-amz-cf-id", name: "Amazon CloudFront", category: "edge" },
  { header: "x-azure-ref", name: "Azure Front Door", category: "edge" },
  { header: "x-akamai-transformed", name: "Akamai", category: "edge" },
  { header: "x-sucuri-id", name: "Sucuri WAF", category: "edge" },
  { header: "x-vercel-id", name: "Vercel", category: "hosting" },
  { header: "x-nf-request-id", name: "Netlify", category: "hosting" },
  { header: "x-github-request-id", name: "GitHub Pages", category: "hosting" },
  { header: "fly-request-id", name: "Fly.io", category: "hosting" },
  { header: "x-render-origin-server", name: "Render", category: "hosting" },
  { header: "x-aspnet-version", name: "ASP.NET", category: "framework", version: true },
  { header: "x-aspnetmvc-version", name: "ASP.NET MVC", category: "framework", version: true },
  { header: "x-drupal-cache", name: "Drupal", category: "platform" },
  { header: "x-drupal-dynamic-cache", name: "Drupal", category: "platform" },
  { header: "x-shopify-stage", name: "Shopify", category: "platform" },
  { header: "x-wix-request-id", name: "Wix", category: "platform" },
  { header: "x-magento-cache-debug", name: "Magento", category: "platform" }
];

// Nome do cookie (antes do "="). O valor nunca é lido.
const COOKIE_RULES: { pattern: RegExp; name: string; category: TechnologyCategory }[] = [
  { pattern: /^PHPSESSID$/i, name: "PHP", category: "framework" },
  { pattern: /^JSESSIONID$/i, name: "Java (servlet)", category: "framework" },
  { pattern: /^ASP\.NET_SessionId$/i, name: "ASP.NET", category: "framework" },
  { pattern: /^\.AspNetCore\./i, name: "ASP.NET Core", category: "framework" },
  { pattern: /^laravel_session$/i, name: "Laravel", category: "framework" },
  { pattern: /^connect\.sid$/i, name: "Express", category: "framework" },
  { pattern: /^_rails_session$|^_session_id$/i, name: "Ruby on Rails", category: "framework" },
  { pattern: /^csrftoken$/i, name: "Django", category: "framework" },
  { pattern: /^(wordpress_|wp-settings-)/i, name: "WordPress", category: "platform" },
  { pattern: /^_shopify_/i, name: "Shopify", category: "platform" },
  { pattern: /^__cf_bm$|^__cflb$/i, name: "Cloudflare", category: "edge" },
  { pattern: /^AWSALB(CORS)?$/i, name: "AWS Elastic Load Balancing", category: "edge" },
  { pattern: /^BIGipServer/i, name: "F5 BIG-IP", category: "edge" },
  { pattern: /^incap_ses_|^visid_incap_/i, name: "Imperva Incapsula", category: "edge" }
];

const CA_RULES: { pattern: RegExp; name: string }[] = [
  { pattern: /let'?s encrypt|^R\d+$|^E\d+$/i, name: "Let's Encrypt" },
  { pattern: /digicert/i, name: "DigiCert" },
  { pattern: /sectigo|comodo/i, name: "Sectigo" },
  { pattern: /globalsign/i, name: "GlobalSign" },
  { pattern: /google trust services|^GTS /i, name: "Google Trust Services" },
  { pattern: /amazon/i, name: "Amazon Trust Services" },
  { pattern: /microsoft/i, name: "Microsoft" },
  { pattern: /zerossl/i, name: "ZeroSSL" },
  { pattern: /godaddy|starfield/i, name: "GoDaddy" },
  { pattern: /entrust/i, name: "Entrust" },
  { pattern: /certisign/i, name: "Certisign" }
];

const MX_RULES: { pattern: RegExp; name: string }[] = [
  { pattern: /(^|\.)(google\.com|googlemail\.com)$/i, name: "Google Workspace" },
  { pattern: /\.mail\.protection\.outlook\.com$|(^|\.)outlook\.com$/i, name: "Microsoft 365" },
  { pattern: /(^|\.)zoho\.(com|eu|in)$/i, name: "Zoho Mail" },
  { pattern: /(^|\.)protonmail\.ch$/i, name: "Proton Mail" },
  { pattern: /(^|\.)mimecast\.com$/i, name: "Mimecast" },
  { pattern: /(^|\.)pphosted\.com$/i, name: "Proofpoint" },
  { pattern: /(^|\.)barracudanetworks\.com$/i, name: "Barracuda" },
  { pattern: /(^|\.)titan\.email$/i, name: "Titan" },
  { pattern: /(^|\.)locaweb\.com\.br$/i, name: "Locaweb" },
  { pattern: /(^|\.)amazonaws\.com$/i, name: "Amazon SES" }
];

const NS_RULES: { pattern: RegExp; name: string }[] = [
  { pattern: /\.ns\.cloudflare\.com$/i, name: "Cloudflare DNS" },
  { pattern: /\.awsdns-\d+\./i, name: "Amazon Route 53" },
  { pattern: /\.azure-dns\./i, name: "Azure DNS" },
  { pattern: /\.googledomains\.com$|^ns-cloud-[a-z]\d\.googledomains\.com$/i, name: "Google Cloud DNS" },
  { pattern: /(^|\.)dns\.br$/i, name: "Registro.br" },
  { pattern: /(^|\.)domaincontrol\.com$/i, name: "GoDaddy" },
  { pattern: /(^|\.)nsone\.net$/i, name: "NS1" },
  { pattern: /(^|\.)ultradns\./i, name: "UltraDNS" },
  { pattern: /(^|\.)akam\.net$/i, name: "Akamai Edge DNS" },
  { pattern: /(^|\.)digitalocean\.com$/i, name: "DigitalOcean" },
  { pattern: /(^|\.)locaweb\.com\.br$/i, name: "Locaweb" },
  { pattern: /(^|\.)hostgator\.com(\.br)?$/i, name: "HostGator" },
  { pattern: /(^|\.)vercel-dns\.com$/i, name: "Vercel DNS" }
];

const clip = (value: string) => value.replace(/[\r\n\t]+/g, " ").slice(0, 120);

/** Uma linha por (categoria, nome); a primeira evidência vence e uma versão encontrada depois é aproveitada. */
function collector() {
  const found = new Map<string, Technology>();
  return {
    add(t: Technology) {
      const key = `${t.category}:${t.name}`;
      const existing = found.get(key);
      if (!existing) found.set(key, { ...t, version: t.version?.slice(0, 40) || null, evidence: clip(t.evidence) });
      else if (!existing.version && t.version) existing.version = t.version.slice(0, 40);
    },
    list: () => [...found.values()].sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name))
  };
}

function matchRules(value: string, rules: Rule[], label: string, add: (t: Technology) => void) {
  for (const rule of rules) {
    const match = rule.pattern.exec(value);
    if (match) add({ name: rule.name, category: rule.category, version: match[1] ?? null, evidence: `${label}: ${value}` });
  }
}

/** Tecnologias na resposta HTTP e no certificado. Função pura. */
export function detectFromResponse(response: Pick<ObservedResponse, "header" | "cookies" | "tls">): Technology[] {
  const found = collector();
  const server = response.header("server");
  if (server) matchRules(server, SERVER_RULES, "Server", found.add);
  const poweredBy = response.header("x-powered-by");
  if (poweredBy) matchRules(poweredBy, POWERED_BY_RULES, "X-Powered-By", found.add);
  const generator = response.header("x-generator");
  if (generator) matchRules(generator, [...POWERED_BY_RULES, { name: "Drupal", category: "platform", pattern: /\bDrupal(?:\s+(\d+))?/i }], "X-Generator", found.add);
  for (const rule of HEADER_RULES) {
    const value = response.header(rule.header);
    if (value !== undefined) found.add({ name: rule.name, category: rule.category, version: rule.version ? value.trim() : null, evidence: rule.version ? `${rule.header}: ${value}` : `Cabeçalho ${rule.header} presente` });
  }
  const via = response.header("via");
  if (via && /cloudfront/i.test(via)) found.add({ name: "Amazon CloudFront", category: "edge", version: null, evidence: `Via: ${via}` });
  if (via && /varnish/i.test(via)) found.add({ name: "Varnish", category: "edge", version: null, evidence: `Via: ${via}` });
  if (response.header("x-served-by")?.includes("cache-") && response.header("x-cache") !== undefined) found.add({ name: "Fastly", category: "edge", version: null, evidence: "Cabeçalhos X-Served-By (cache-…) e X-Cache presentes" });
  for (const cookie of response.cookies) {
    const name = cookie.split("=", 1)[0].trim();
    const rule = COOKIE_RULES.find(r => r.pattern.test(name));
    // A evidência cita só o padrão do nome, nunca o valor.
    if (rule) found.add({ name: rule.name, category: rule.category, version: null, evidence: `Cookie com nome característico (${name.replace(/^(.{0,24}).*$/, "$1")})` });
  }
  const issuer = response.tls?.issuer;
  if (issuer) {
    const ca = CA_RULES.find(r => r.pattern.test(issuer));
    found.add({ name: ca?.name ?? issuer.slice(0, 60), category: "certificate", version: null, evidence: `Emissor do certificado: ${issuer}` });
  }
  return found.list();
}

/** Provedor de e-mail (MX do domínio de e-mail mais próximo) e de DNS (NS do apex da zona). Erros do resolvedor = nada detectado. */
export async function detectFromDns(hostname: string, dns: DnsLookup): Promise<Technology[]> {
  const found = collector();
  const chain = ancestors(hostname);
  try {
    for (const name of chain) {
      const ns = await records(dns.ns(name));
      if (!ns.length) continue;
      for (const host of ns) {
        const rule = NS_RULES.find(r => r.pattern.test(host.replace(/\.$/, "")));
        if (rule) found.add({ name: rule.name, category: "dns", version: null, evidence: `NS de ${name}: ${host}` });
      }
      break;
    }
  } catch { /* resolvedor indisponível: sem inventário de DNS */ }
  try {
    for (const name of chain) {
      const mx: MxRecord[] = await records(dns.mx(name));
      if (!mx.length) continue;
      for (const record of mx.sort((a, b) => a.priority - b.priority)) {
        const rule = MX_RULES.find(r => r.pattern.test(record.exchange.replace(/\.$/, "")));
        if (rule) found.add({ name: rule.name, category: "email", version: null, evidence: `MX de ${name}: ${record.exchange}` });
      }
      break;
    }
  } catch { /* idem */ }
  return found.list();
}

export function mergeTechnologies(...lists: Technology[][]): Technology[] {
  const found = collector();
  for (const t of lists.flat()) found.add(t);
  return found.list();
}
