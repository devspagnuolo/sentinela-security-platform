import { z } from "zod";
import { WEBHOOK_EVENT_TYPES, webhookUrlError, type WebhookEvent } from "./webhooks";
import { normalizeHostPattern } from "./scope";
import { AUDIT_RETENTION_OPTIONS, CONTACT_RETENTION_OPTIONS, DATA_RETENTION_OPTIONS } from "./retention-options";

export const createAssetSchema = z.object({
  name: z.string().trim().max(100).optional().default(""),
  url: z.string().trim().min(1, "Informe a URL do ativo.").max(2048),
  owner: z.string().trim().max(100).optional().default(""),
  kind: z.enum(["Web application", "API"]).optional().default("Web application"),
  authorizationId: z.uuid({ error: "Selecione a autorização de escopo que cobre este ativo." })
});

export type CreateAssetInput = z.infer<typeof createAssetSchema>;

export function firstIssue(error: z.ZodError): string {
  return error.issues[0]?.message ?? "Dados inválidos.";
}

const email = z.string().trim().toLowerCase().pipe(z.email("Informe um e-mail válido.")).pipe(z.string().max(254));
const role = z.enum(["owner", "admin", "analyst", "viewer"], { error: "Papel inválido." });

export const loginSchema = z.object({ email: z.string().trim().max(254), password: z.string().max(256) });

export const createUserSchema = z.object({
  email,
  name: z.string().trim().min(2, "Informe o nome.").max(100),
  role,
  password: z.string()
});

export const updateUserSchema = z.object({
  role: role.optional(),
  disabled: z.boolean().optional(),
  name: z.string().trim().min(2).max(100).optional(),
  password: z.string().optional(),
  resetMfa: z.literal(true).optional()
}).refine(v => Object.values(v).some(x => x !== undefined), "Nada para alterar.");

export const changePasswordSchema = z.object({ currentPassword: z.string().max(256), newPassword: z.string() });

export async function parseJson<T>(request: Request, schema: z.ZodType<T>): Promise<{ data: T } | { error: string }> {
  let body: unknown;
  try { body = await request.json(); } catch { return { error: "Corpo da requisição deve ser JSON válido." }; }
  const parsed = schema.safeParse(body);
  return parsed.success ? { data: parsed.data } : { error: firstIssue(parsed.error) };
}

export const mfaVerifySchema = z.object({ challenge: z.string().min(10).max(128), code: z.string().trim().min(6).max(20) });
export const mfaCodeSchema = z.object({ code: z.string().trim().min(6).max(20) });
export const passwordConfirmSchema = z.object({ password: z.string().max(256) });
export const organizationSchema = z.object({ requireMfa: z.boolean().optional(), name: z.string().trim().min(2).max(100).optional() }).refine(v => Object.values(v).some(x => x !== undefined), "Nada para alterar.");

const domain = z.string().trim().toLowerCase().regex(/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/, "Domínio inválido.");
export const ssoConfigSchema = z.object({
  issuer: z.string().trim().max(512).pipe(z.url({ protocol: /^https?$/, error: "Informe a URL do emissor (issuer)." })),
  clientId: z.string().trim().min(1, "Informe o client ID.").max(255),
  clientSecret: z.string().trim().min(1).max(1024).optional(),
  allowedDomains: z.array(domain).min(1, "Informe ao menos um domínio de e-mail.").max(20),
  enabled: z.boolean(),
  enforced: z.boolean().default(false),
  jitRole: z.enum(["analyst", "viewer"]).nullable().default(null)
}).refine(v => !v.enforced || v.enabled, "Ative o SSO antes de torná-lo obrigatório.");

const hostList = (label: string) => z.array(z.string()).max(50).transform((items, ctx) => {
  const out: string[] = [];
  for (const raw of items) {
    if (!raw.trim()) continue;
    const host = normalizeHostPattern(raw);
    if (!host) { ctx.addIssue({ code: "custom", message: `${label}: "${raw.trim().slice(0, 80)}" não é um hostname válido (use app.cliente.com ou *.cliente.com).` }); return z.NEVER; }
    out.push(host);
  }
  return [...new Set(out)];
});
const day = z.iso.date({ error: "Data inválida." });
const optionalText = (max: number) => z.string().trim().max(max).optional().default("");

export const authorizationSchema = z.object({
  reference: z.string().trim().min(3, "Informe a referência do documento (contrato, termo, chamado).").max(120),
  clientName: optionalText(120),
  hostnames: hostList("Hostnames").pipe(z.array(z.string()).min(1, "Informe ao menos um hostname autorizado.")),
  excludedHostnames: hostList("Exclusões").optional().default([]),
  validFrom: day.optional(),
  validUntil: day,
  emergencyContact: optionalText(200),
  notes: optionalText(2000)
}).transform(v => ({
  ...v,
  // Datas do formulário valem o dia inteiro no fuso de Brasília.
  validFrom: v.validFrom ? new Date(`${v.validFrom}T00:00:00-03:00`) : null,
  validUntil: new Date(`${v.validUntil}T23:59:59.999-03:00`)
})).refine(v => !v.validFrom || v.validFrom <= v.validUntil, "O início precisa ser anterior ao fim da validade.")
  .refine(v => v.validUntil.getTime() - Date.now() <= 1000 * 60 * 60 * 24 * 731, "A validade máxima é de 2 anos; renove com uma nova autorização.");

export const revokeSchema = z.object({ reason: z.string().trim().min(3, "Informe o motivo da revogação.").max(500) });

export const findingStatusSchema = z.discriminatedUnion("status", [
  z.object({ status: z.literal("open"), reason: optionalText(1000) }),
  z.object({ status: z.literal("fixed"), reason: optionalText(1000) }),
  z.object({ status: z.literal("false_positive"), reason: z.string().trim().min(5, "Explique por que é um falso positivo.").max(1000) }),
  z.object({ status: z.literal("accepted"), reason: z.string().trim().min(5, "Registre a justificativa do aceite de risco.").max(1000), acceptedUntil: day })
], { error: "Situação inválida." }).transform(v => v.status === "accepted" ? { ...v, acceptedUntil: new Date(`${v.acceptedUntil}T23:59:59.999-03:00`) } : v)
  .refine(v => v.status !== "accepted" || (v.acceptedUntil > new Date() && v.acceptedUntil.getTime() - Date.now() <= 1000 * 60 * 60 * 24 * 366), "O aceite de risco precisa vencer entre amanhã e 1 ano.");

/** 0 desliga a reavaliação periódica; os demais valores são dias entre execuções. */
export const scheduleSchema = z.object({
  intervalDays: z.union([z.literal(0), z.literal(1), z.literal(7), z.literal(30)], { error: "Escolha manual, diária, semanal ou mensal." })
});
export const markReadSchema = z.object({ ids: z.array(z.string()).max(200).optional() });

export const apiTokenSchema = z.object({
  name: z.string().trim().min(2, "Dê um nome que identifique onde o token será usado.").max(80),
  role: z.enum(["viewer", "analyst"], { error: "Tokens podem ter papel Leitor ou Analista." }),
  days: z.union([z.literal(7), z.literal(30), z.literal(90), z.literal(365)], { error: "Escolha validade de 7, 30, 90 ou 365 dias." })
});

const webhookEvents = z.array(z.enum(WEBHOOK_EVENT_TYPES as [WebhookEvent, ...WebhookEvent[]], { error: "Evento desconhecido." })).min(1, "Escolha ao menos um evento.").max(WEBHOOK_EVENT_TYPES.length)
  .transform(events => [...new Set(events)]);
const webhookUrl = z.string().trim().max(2000).superRefine((value, ctx) => { const error = webhookUrlError(value); if (error) ctx.addIssue({ code: "custom", message: error }); });
export const webhookSchema = z.object({ name: z.string().trim().min(2, "Dê um nome ao webhook.").max(80), url: webhookUrl, events: webhookEvents });
export const webhookUpdateSchema = z.object({ name: webhookSchema.shape.name.optional(), url: webhookUrl.optional(), events: webhookEvents.optional(), enabled: z.boolean().optional() })
  .refine(v => Object.values(v).some(x => x !== undefined), "Nada para alterar.");

export const preferencesSchema = z.object({ emailNotifications: z.boolean({ error: "Informe se quer receber os avisos por e-mail." }) });

const retentionChoice = (options: readonly number[]) => z.literal(options as number[], { error: `Prazo aceito: ${options.join(", ")} dias.` });
export const retentionSchema = z.object({
  auditRetentionDays: retentionChoice(AUDIT_RETENTION_OPTIONS).optional(),
  assessmentRetentionDays: retentionChoice(DATA_RETENTION_OPTIONS).nullable().optional(),
  closedFindingRetentionDays: retentionChoice(DATA_RETENTION_OPTIONS).nullable().optional(),
  scopeContactRetentionDays: retentionChoice(CONTACT_RETENTION_OPTIONS).optional()
}).refine(v => Object.values(v).some(x => x !== undefined), "Nada para alterar.");

export const anonymizeSchema = z.object({ confirmEmail: z.string().trim().min(1, "Digite o e-mail da pessoa para confirmar.").max(320) });

// Conectores de nuvem: só credenciais de leitura (docs/conectores.md explica as permissões mínimas).
const cloudCredentials = z.discriminatedUnion("provider", [
  z.object({ provider: z.literal("cloudflare"), apiToken: z.string().trim().regex(/^[A-Za-z0-9_-]{20,200}$/, "Token da Cloudflare inválido.") }),
  z.object({
    provider: z.literal("aws_route53"),
    accessKeyId: z.string().trim().regex(/^AKIA[A-Z0-9]{16}$/, "Access key ID inválida (use a chave de um usuário IAM, que começa com AKIA)."),
    secretAccessKey: z.string().trim().regex(/^[A-Za-z0-9/+=]{40}$/, "Secret access key inválida.")
  })
], { error: "Provedor não suportado." });
const connectorName = z.string().trim().min(2, "Dê um nome ao conector.").max(80);
export const connectorSchema = z.object({ name: connectorName, credentials: cloudCredentials });
export const connectorUpdateSchema = z.object({ name: connectorName.optional(), enabled: z.boolean().optional(), credentials: cloudCredentials.optional() })
  .refine(v => Object.values(v).some(x => x !== undefined), "Nada para alterar.");
