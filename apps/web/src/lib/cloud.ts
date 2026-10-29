import { createHash, createHmac } from "node:crypto";
import { isIP } from "node:net";
import { isPublicAddress } from "./network";

/**
 * Conectores de nuvem somente leitura: listam as zonas DNS da organização para
 * descobrir hostnames expostos. Toda chamada é GET, e só para os endpoints
 * oficiais dos provedores (lista fixa abaixo): o conector não altera nada na
 * conta e não pode ser usado para alcançar outros destinos. Descobrir um
 * hostname não autoriza avaliá-lo; isso continua exigindo um escopo aprovado.
 */
export const CLOUD_PROVIDERS = {
  cloudflare: "Cloudflare (DNS)",
  aws_route53: "AWS Route 53"
} as const;
export type CloudProvider = keyof typeof CLOUD_PROVIDERS;

export type CloudCredentials =
  | { provider: "cloudflare"; apiToken: string }
  | { provider: "aws_route53"; accessKeyId: string; secretAccessKey: string };

export type DnsRecord = { zone: string; hostname: string; type: "A" | "AAAA" | "CNAME" | "ALIAS"; target: string };
/** Hostname descoberto, com todos os registros que apontam para ele. */
export type DiscoveredHost = { zone: string; hostname: string; recordTypes: string[]; targets: string[]; internal: boolean };

export type HttpResponse = { status: number; text(): Promise<string> };
export type CloudHttp = (url: string, headers: Record<string, string>) => Promise<HttpResponse>;

const ALLOWED_HOSTS = new Set(["api.cloudflare.com", "route53.amazonaws.com"]);
const TIMEOUT_MS = 15_000;
export const MAX_ZONES = 200;
export const MAX_HOSTS = 5000;

export class CloudError extends Error {}

/** GET com tempo limite, só para os provedores conhecidos e sem seguir redirecionamentos. */
export const defaultHttp: CloudHttp = async (url, headers) => {
  const response = await fetch(url, { method: "GET", headers, redirect: "error", signal: AbortSignal.timeout(TIMEOUT_MS) });
  return { status: response.status, text: () => response.text() };
};

function guarded(http: CloudHttp): CloudHttp {
  return (url, headers) => {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" || !ALLOWED_HOSTS.has(parsed.hostname)) throw new CloudError("Destino não permitido para conectores de nuvem.");
    return http(url, headers);
  };
}

const normalizeHost = (name: string) => name.toLowerCase().replace(/\.$/, "");

/** Junta os registros por hostname. Curingas (*.dominio) e nomes inválidos ficam de fora. */
export function groupHosts(records: DnsRecord[]): DiscoveredHost[] {
  const hosts = new Map<string, DiscoveredHost>();
  for (const r of records) {
    const hostname = normalizeHost(r.hostname);
    if (hostname.includes("*") || !/^[a-z0-9_.-]+$/.test(hostname) || !hostname.includes(".")) continue;
    const host = hosts.get(hostname) ?? { zone: normalizeHost(r.zone), hostname, recordTypes: [], targets: [], internal: false };
    if (!host.recordTypes.includes(r.type)) host.recordTypes.push(r.type);
    const target = r.type === "CNAME" || r.type === "ALIAS" ? normalizeHost(r.target) : r.target;
    if (!host.targets.includes(target) && host.targets.length < 20) host.targets.push(target);
    hosts.set(hostname, host);
  }
  // Interno: só aponta para IPs privados (ex.: zona pública com registros da rede interna).
  return [...hosts.values()].slice(0, MAX_HOSTS).map(h => ({ ...h, internal: h.targets.every(t => isIP(t) > 0 && !isPublicAddress(t)) }))
    .sort((a, b) => a.hostname.localeCompare(b.hostname));
}

// ---- Cloudflare ------------------------------------------------------------------------

type CloudflarePage<T> = { success: boolean; errors?: { message: string }[]; result: T[]; result_info?: { page: number; total_pages: number } };

async function cloudflareGet<T>(http: CloudHttp, token: string, path: string): Promise<CloudflarePage<T>> {
  const response = await http(`https://api.cloudflare.com/client/v4${path}`, { Authorization: `Bearer ${token}`, Accept: "application/json" });
  let body: CloudflarePage<T>;
  try { body = JSON.parse(await response.text()); } catch { throw new CloudError(`Cloudflare respondeu HTTP ${response.status} sem JSON.`); }
  if (response.status === 401 || response.status === 403) throw new CloudError("Cloudflare recusou o token. Confira se ele tem as permissões Zone:Read e DNS:Read.");
  if (!body.success) throw new CloudError(`Cloudflare: ${body.errors?.[0]?.message ?? `HTTP ${response.status}`}`);
  return body;
}

async function cloudflareAll<T>(http: CloudHttp, token: string, path: string, limit: number): Promise<T[]> {
  const items: T[] = [];
  for (let page = 1; items.length < limit; page++) {
    const body = await cloudflareGet<T>(http, token, `${path}${path.includes("?") ? "&" : "?"}per_page=100&page=${page}`);
    items.push(...body.result);
    if (!body.result_info || page >= body.result_info.total_pages || !body.result.length) break;
  }
  return items.slice(0, limit);
}

async function cloudflareRecords(http: CloudHttp, token: string): Promise<DnsRecord[]> {
  const zones = await cloudflareAll<{ id: string; name: string }>(http, token, "/zones?status=active", MAX_ZONES);
  const records: DnsRecord[] = [];
  for (const zone of zones) {
    if (!/^[a-f0-9]{32}$/.test(zone.id)) continue;
    const rows = await cloudflareAll<{ name: string; type: string; content: string }>(http, token, `/zones/${zone.id}/dns_records`, MAX_HOSTS);
    for (const r of rows) if (r.type === "A" || r.type === "AAAA" || r.type === "CNAME") records.push({ zone: zone.name, hostname: r.name, type: r.type, target: r.content });
    if (records.length >= MAX_HOSTS * 2) break;
  }
  return records;
}

// ---- AWS (assinatura SigV4 e Route 53) -------------------------------------------------

const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");
const hmac = (key: Buffer | string, value: string) => createHmac("sha256", key).update(value).digest();
/** Codificação RFC 3986 exigida pela assinatura (encodeURIComponent deixa !'()* sem codificar). */
export const awsEncode = (value: string) => encodeURIComponent(value).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

/** Assina uma requisição com AWS Signature Version 4 e devolve os cabeçalhos a enviar. */
export function signV4(input: { method: string; url: string; headers?: Record<string, string>; body?: string; region: string; service: string; accessKeyId: string; secretAccessKey: string; now: Date }): Record<string, string> {
  const url = new URL(input.url);
  const amzDate = input.now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const day = amzDate.slice(0, 8);
  const headers: Record<string, string> = { ...input.headers, host: url.host, "x-amz-date": amzDate };
  const names = Object.keys(headers).map(h => h.toLowerCase()).sort();
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v.trim().replace(/\s+/g, " ")]));
  const query = [...url.searchParams.entries()].map(([k, v]) => [awsEncode(k), awsEncode(v)]).sort(([a, x], [b, y]) => a === b ? (x < y ? -1 : 1) : a < b ? -1 : 1).map(([k, v]) => `${k}=${v}`).join("&");
  const path = url.pathname.split("/").map(segment => awsEncode(decodeURIComponent(segment))).join("/") || "/";
  const canonical = [input.method, path, query, names.map(n => `${n}:${lower[n]}\n`).join(""), names.join(";"), sha256(input.body ?? "")].join("\n");
  const scope = `${day}/${input.region}/${input.service}/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonical)].join("\n");
  const key = hmac(hmac(hmac(hmac(`AWS4${input.secretAccessKey}`, day), input.region), input.service), "aws4_request");
  const signature = createHmac("sha256", key).update(toSign).digest("hex");
  return { ...headers, Authorization: `AWS4-HMAC-SHA256 Credential=${input.accessKeyId}/${scope}, SignedHeaders=${names.join(";")}, Signature=${signature}` };
}

const xmlDecode = (value: string) => value.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"").replace(/&apos;/g, "'").replace(/&amp;/g, "&");
const xmlAll = (xml: string, tag: string) => [...xml.matchAll(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, "g"))].map(m => m[1]);
const xmlOne = (xml: string, tag: string) => { const v = xmlAll(xml, tag)[0]; return v === undefined ? undefined : xmlDecode(v.trim()); };
/** Route 53 escapa caracteres especiais em octal (ex.: \052 = "*"). */
const route53Name = (value: string) => value.replace(/\\(\d{3})/g, (_, octal: string) => String.fromCharCode(parseInt(octal, 8)));

async function route53Get(http: CloudHttp, creds: { accessKeyId: string; secretAccessKey: string }, path: string, now: () => Date): Promise<string> {
  const url = `https://route53.amazonaws.com${path}`;
  const response = await http(url, signV4({ method: "GET", url, region: "us-east-1", service: "route53", accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, now: now() }));
  const body = await response.text();
  if (response.status === 403 || response.status === 401) throw new CloudError("A AWS recusou as credenciais. Confira a chave e a política com route53:ListHostedZones e route53:ListResourceRecordSets.");
  if (response.status !== 200) throw new CloudError(`AWS Route 53: ${xmlOne(body, "Message") ?? `HTTP ${response.status}`}`);
  return body;
}

async function route53Records(http: CloudHttp, creds: { accessKeyId: string; secretAccessKey: string }, now: () => Date): Promise<DnsRecord[]> {
  const zones: { id: string; name: string }[] = [];
  for (let marker: string | undefined; zones.length < MAX_ZONES;) {
    const xml = await route53Get(http, creds, `/2013-04-01/hostedzone?maxitems=100${marker ? `&marker=${awsEncode(marker)}` : ""}`, now);
    for (const zone of xmlAll(xml, "HostedZone")) {
      // Zonas privadas (VPC) não são superfície exposta à internet.
      if (xmlOne(zone, "PrivateZone") === "true") continue;
      const id = xmlOne(zone, "Id")?.replace("/hostedzone/", "");
      if (id && /^[A-Z0-9]+$/.test(id)) zones.push({ id, name: route53Name(xmlOne(zone, "Name") ?? "") });
    }
    marker = xmlOne(xml, "IsTruncated") === "true" ? xmlOne(xml, "NextMarker") : undefined;
    if (!marker) break;
  }
  const records: DnsRecord[] = [];
  for (const zone of zones.slice(0, MAX_ZONES)) {
    let next: { name: string; type: string; identifier?: string } | undefined;
    do {
      const params = next ? `&name=${awsEncode(next.name)}&type=${awsEncode(next.type)}${next.identifier ? `&identifier=${awsEncode(next.identifier)}` : ""}` : "";
      const xml = await route53Get(http, creds, `/2013-04-01/hostedzone/${zone.id}/rrset?maxitems=300${params}`, now);
      for (const set of xmlAll(xml, "ResourceRecordSet")) {
        const type = xmlOne(set, "Type"), name = route53Name(xmlOne(set, "Name") ?? "");
        if (type !== "A" && type !== "AAAA" && type !== "CNAME") continue;
        const alias = xmlOne(set, "DNSName");
        if (alias) records.push({ zone: zone.name, hostname: name, type: "ALIAS", target: route53Name(alias) });
        else for (const value of xmlAll(set, "Value")) records.push({ zone: zone.name, hostname: name, type, target: xmlDecode(value.trim()) });
      }
      next = xmlOne(xml, "IsTruncated") === "true" ? { name: xmlOne(xml, "NextRecordName") ?? "", type: xmlOne(xml, "NextRecordType") ?? "", identifier: xmlOne(xml, "NextRecordIdentifier") } : undefined;
    } while (next && records.length < MAX_HOSTS * 2);
    if (records.length >= MAX_HOSTS * 2) break;
  }
  return records;
}

// ---- Entrada única ---------------------------------------------------------------------

/** Lista os hostnames das zonas públicas da conta. Erros de credencial ou do provedor viram CloudError. */
export async function discoverHosts(creds: CloudCredentials, deps: { http?: CloudHttp; now?: () => Date } = {}): Promise<{ zones: number; hosts: DiscoveredHost[] }> {
  const http = guarded(deps.http ?? defaultHttp);
  let records: DnsRecord[];
  try {
    records = creds.provider === "cloudflare" ? await cloudflareRecords(http, creds.apiToken) : await route53Records(http, creds, deps.now ?? (() => new Date()));
  } catch (error) {
    if (error instanceof CloudError) throw error;
    throw new CloudError(`Falha ao consultar ${CLOUD_PROVIDERS[creds.provider]}: ${error instanceof Error ? error.message : "erro de rede"}.`);
  }
  return { zones: new Set(records.map(r => normalizeHost(r.zone))).size, hosts: groupHosts(records) };
}

/** Pedaço da credencial para identificá-la na interface sem revelar o segredo. */
export function credentialHint(creds: CloudCredentials) {
  return creds.provider === "cloudflare" ? `token …${creds.apiToken.slice(-4)}` : `${creds.accessKeyId.slice(0, 4)}…${creds.accessKeyId.slice(-4)}`;
}
