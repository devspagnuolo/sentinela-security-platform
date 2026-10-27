import nodemailer from "nodemailer";
import { appLink } from "./webhooks";

/**
 * Envio de e-mail por SMTP. Sem SENTINELA_SMTP_URL e SENTINELA_MAIL_FROM, nada é
 * enviado e os avisos ficam só na caixa de notificações da aplicação.
 * Exemplos: smtps://usuario:senha@smtp.provedor.com:465 · smtp://usuario:senha@smtp.provedor.com:587 (STARTTLS obrigatório).
 */
export type MailMessage = { to: string; subject: string; text: string; html: string };
export type MailTransport = (message: MailMessage) => Promise<void>;

export function mailSettings(env: NodeJS.ProcessEnv = process.env) {
  const url = env.SENTINELA_SMTP_URL?.trim(), from = env.SENTINELA_MAIL_FROM?.trim();
  return { enabled: Boolean(url && from), url: url ?? "", from: from ?? "" };
}

/** Remetente e servidor sem a senha, para exibir na interface. */
export function describeMailSettings(env: NodeJS.ProcessEnv = process.env) {
  const settings = mailSettings(env);
  if (!settings.enabled) return null;
  try {
    const url = new URL(settings.url);
    return { from: settings.from, server: `${url.hostname}:${url.port || (url.protocol === "smtps:" ? 465 : 587)}` };
  } catch { return { from: settings.from, server: "URL SMTP inválida" }; }
}

let cached: { url: string; send: MailTransport } | undefined;

/** Transporte SMTP real (reaproveitado entre envios). STARTTLS é exigido quando a URL não é smtps://. */
export function smtpTransport(env: NodeJS.ProcessEnv = process.env): MailTransport {
  const settings = mailSettings(env);
  if (!settings.enabled) throw new Error("E-mail não configurado (SENTINELA_SMTP_URL e SENTINELA_MAIL_FROM).");
  if (cached?.url === settings.url) return cached.send;
  const url = new URL(settings.url);
  const transporter = nodemailer.createTransport({
    host: url.hostname, port: Number(url.port) || (url.protocol === "smtps:" ? 465 : 587), secure: url.protocol === "smtps:",
    requireTLS: url.protocol !== "smtps:" && env.SENTINELA_SMTP_ALLOW_PLAIN !== "1",
    auth: url.username ? { user: decodeURIComponent(url.username), pass: decodeURIComponent(url.password) } : undefined,
    connectionTimeout: 10_000, greetingTimeout: 10_000, socketTimeout: 20_000
  });
  const send: MailTransport = async message => { await transporter.sendMail({ from: settings.from, ...message }); };
  cached = { url: settings.url, send };
  return send;
}

const escapeHtml = (value: string) => value.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[c]!);
// Quebras de linha e caracteres de controle no assunto permitiriam injetar cabeçalhos.
const oneLine = (value: string) => value.replace(/[\r\n\t\u0000-\u001f]+/g, " ").trim();

/** E-mail de um aviso da caixa de notificações (texto e HTML simples, sem recursos externos). */
export function notificationEmail(n: { title: string; body: string; link: string | null }, recipient: { email: string; name: string }, env: NodeJS.ProcessEnv = process.env): MailMessage {
  const link = n.link ? appLink(n.link, env) : null;
  const prefs = appLink("/conta", env);
  const footer = `Você recebe este e-mail porque tem acesso ao Sentinela. Para deixar de receber, desative os avisos por e-mail em Minha conta${prefs ? `: ${prefs}` : "."}`;
  const text = [`Olá, ${recipient.name}.`, "", n.title, n.body ? `\n${n.body}` : "", link ? `\nAbrir no Sentinela: ${link}` : "", "", "--", footer].filter(line => line !== "").join("\n");
  const html = `<!doctype html><html lang="pt-BR"><body style="font-family:Arial,Helvetica,sans-serif;color:#17302a;background:#f4f7f5;padding:24px">
<div style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #dce9e1;border-radius:12px;padding:24px">
<p style="margin:0 0 4px;font-size:12px;color:#176b53;font-weight:bold;letter-spacing:.06em">SENTINELA</p>
<h1 style="font-size:18px;margin:0 0 12px">${escapeHtml(n.title)}</h1>
${n.body ? `<p style="font-size:14px;line-height:1.5;margin:0 0 16px;white-space:pre-line">${escapeHtml(n.body)}</p>` : ""}
${link ? `<p style="margin:0 0 8px"><a href="${escapeHtml(link)}" style="display:inline-block;background:#176b53;color:#fff;text-decoration:none;padding:10px 16px;border-radius:8px;font-size:14px">Abrir no Sentinela</a></p>` : ""}
</div>
<p style="max-width:560px;margin:12px auto 0;font-size:12px;color:#5b6f66">${escapeHtml(footer)}</p>
</body></html>`;
  return { to: recipient.email, subject: oneLine(`[Sentinela] ${n.title}`).slice(0, 200), text, html };
}
