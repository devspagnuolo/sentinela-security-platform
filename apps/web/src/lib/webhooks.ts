import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { isIP, type LookupFunction } from "node:net";
import { isPublicAddress } from "./network";

export { TEST_EVENT, WEBHOOK_EVENT_TYPES, WEBHOOK_EVENTS, type WebhookEvent } from "./webhook-events";

export const SIGNATURE_HEADER = "Sentinela-Signature";
const USER_AGENT = "Sentinela-Webhooks/1.0";
const TIMEOUT_MS = 10_000;

export const generateWebhookSecret = () => `whsec_${randomBytes(32).toString("base64url")}`;

/**
 * Assinatura no formato "t=<unix>,v1=<hex>", com v1 = HMAC-SHA256(segredo, "<t>.<corpo>").
 * O timestamp no conteúdo assinado permite ao destinatário recusar reenvios antigos (replay).
 */
export function signPayload(secret: string, body: string, timestamp: number) {
  return `t=${timestamp},v1=${createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex")}`;
}

/** Verificação do lado de quem recebe (usada nos testes e documentada em docs/api.md). */
export function verifySignature(secret: string, body: string, header: string, now = Date.now(), toleranceSeconds = 300) {
  const parts = Object.fromEntries(header.split(",").map(p => p.split("=", 2) as [string, string]));
  const t = Number(parts.t);
  if (!Number.isInteger(t) || !parts.v1 || Math.abs(now / 1000 - t) > toleranceSeconds) return false;
  const expected = Buffer.from(signPayload(secret, body, t).split("v1=")[1], "hex");
  const given = Buffer.from(parts.v1, "hex");
  return given.length === expected.length && timingSafeEqual(given, expected);
}

/** O operador pode liberar destinos em rede privada (ex.: um coletor interno); por padrão só endereços públicos. */
export const allowPrivateTargets = (env: NodeJS.ProcessEnv = process.env) => env.SENTINELA_WEBHOOK_ALLOW_PRIVATE === "1";

/** Valida a URL ao cadastrar: HTTPS, sem credenciais embutidas e, se for IP literal, público. */
export function webhookUrlError(raw: string, env: NodeJS.ProcessEnv = process.env): string | null {
  let url: URL;
  try { url = new URL(raw); } catch { return "Informe uma URL válida."; }
  if (url.protocol !== "https:") return "O webhook precisa usar HTTPS.";
  if (url.username || url.password) return "Não inclua usuário ou senha na URL; use o segredo de assinatura.";
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (isIP(host) && !isPublicAddress(host) && !allowPrivateTargets(env)) return "O endereço do webhook não é público.";
  if (!isIP(host) && /^(localhost|.*\.local|.*\.internal|.*\.localhost)$/i.test(host) && !allowPrivateTargets(env)) return "O endereço do webhook não é público.";
  return null;
}

export type WebhookResponse = { status: number };
/** Envio do POST (injetável nos testes). Lança erro em falha de rede ou destino recusado. */
export type WebhookTransport = (url: URL, body: string, headers: Record<string, string>) => Promise<WebhookResponse>;

/**
 * POST para o destino resolvendo o DNS uma única vez: o endereço é validado e a
 * conexão vai a ele (sem nova resolução, o que impede DNS rebinding). Não segue
 * redirecionamentos e não lê o corpo da resposta, só o status.
 */
export const httpsTransport: WebhookTransport = async (url, body, headers) => {
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const addresses = isIP(host) ? [{ address: host, family: isIP(host) }] : await dnsLookup(host, { all: true, verbatim: true }).catch(() => { throw new Error("Não foi possível resolver o hostname do webhook."); });
  if (!addresses.length) throw new Error("Não foi possível resolver o hostname do webhook.");
  if (!allowPrivateTargets() && addresses.some(a => !isPublicAddress(a.address))) throw new Error("O webhook resolve para endereço não público; envio bloqueado.");
  const pinned = addresses[0];
  const lookup: LookupFunction = (_hostname, options, callback) => {
    if (options.all) callback(null, [pinned]);
    else callback(null, pinned.address, pinned.family);
  };
  return new Promise((resolve, reject) => {
    const req = httpsRequest({
      hostname: host, port: url.port || 443, path: `${url.pathname}${url.search}`, method: "POST", lookup, servername: isIP(host) ? undefined : host,
      headers: { ...headers, "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body), "User-Agent": USER_AGENT }, timeout: TIMEOUT_MS
    }, res => {
      res.destroy();
      resolve({ status: res.statusCode ?? 0 });
    });
    req.on("timeout", () => req.destroy(new Error("Tempo limite excedido ao entregar o webhook.")));
    req.on("error", error => reject(error));
    req.end(body);
  });
};

/** Link absoluto para a interface, quando a origem pública está configurada. */
export function appLink(path: string, env: NodeJS.ProcessEnv = process.env) {
  const origin = env.SENTINELA_PUBLIC_ORIGIN?.split(",")[0]?.trim();
  return origin ? `${origin.replace(/\/$/, "")}${path}` : null;
}
