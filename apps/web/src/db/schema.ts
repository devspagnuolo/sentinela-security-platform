import { sql } from "drizzle-orm";
import { bigint, boolean, index, integer, jsonb, pgEnum, pgTable, primaryKey, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";

// Toda tabela de negócio carrega organization_id: o isolamento entre organizações
// é garantido na camada de repositório (src/db/repository.ts), que sempre filtra por ele.

export const roleEnum = pgEnum("role", ["owner", "admin", "analyst", "viewer"]);
export const assetKindEnum = pgEnum("asset_kind", ["Web application", "API"]);
export const severityEnum = pgEnum("severity", ["critical", "high", "medium", "low", "info"]);
export const assessmentStatusEnum = pgEnum("assessment_status", ["queued", "running", "completed", "failed"]);
export const findingStatusEnum = pgEnum("finding_status", ["open", "accepted", "fixed", "false_positive"]);
export const authorizationStatusEnum = pgEnum("authorization_status", ["pending", "approved", "revoked"]);
export const assessmentTriggerEnum = pgEnum("assessment_trigger", ["manual", "scheduled"]);

const timestamps = {
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date())
};
const orgRef = () => uuid("organization_id").notNull().references(() => organizations.id, { onDelete: "cascade" });

export const organizations = pgTable("organizations", {
  id: uuid("id").primaryKey().defaultRandom(),
  slug: text("slug").notNull().unique(),
  name: text("name").notNull(),
  requireMfa: boolean("require_mfa").notNull().default(false),
  ...timestamps
});

export const users = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  email: text("email").notNull(),
  name: text("name").notNull(),
  passwordHash: text("password_hash"),
  disabled: boolean("disabled").notNull().default(false),
  failedLoginCount: integer("failed_login_count").notNull().default(0),
  lockedUntil: timestamp("locked_until", { withTimezone: true }),
  lastLoginAt: timestamp("last_login_at", { withTimezone: true }),
  passwordChangedAt: timestamp("password_changed_at", { withTimezone: true }),
  // Segredos TOTP criptografados com AES-256-GCM (src/lib/crypto.ts).
  totpSecret: text("totp_secret"),
  totpPendingSecret: text("totp_pending_secret"),
  totpEnabledAt: timestamp("totp_enabled_at", { withTimezone: true }),
  totpLastStep: bigint("totp_last_step", { mode: "number" }),
  // Recebe por e-mail os avisos da caixa de notificações (quando o SMTP está configurado).
  emailNotifications: boolean("email_notifications").notNull().default(true),
  ...timestamps
}, t => [uniqueIndex("users_email_lower_idx").on(sql`lower(${t.email})`)]);

export const memberships = pgTable("memberships", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: orgRef(),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  role: roleEnum("role").notNull(),
  ...timestamps
}, t => [uniqueIndex("memberships_org_user_idx").on(t.organizationId, t.userId)]);

// O id da sessão é o SHA-256 do token do cookie: o token em si nunca é gravado.
export const sessions = pgTable("sessions", {
  id: text("id").primaryKey(),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  organizationId: orgRef(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  // password | mfa | sso: login via SSO cumpre a política de MFA da organização (o IdP aplica o próprio MFA).
  authMethod: text("auth_method").notNull().default("password"),
  ip: text("ip"),
  userAgent: text("user_agent")
}, t => [index("sessions_user_idx").on(t.userId), index("sessions_expires_idx").on(t.expiresAt)]);

// Desafio emitido após a senha correta quando o usuário tem MFA; id = SHA-256 do token.
export const mfaChallenges = pgTable("mfa_challenges", {
  id: text("id").primaryKey(),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  organizationId: orgRef(),
  attempts: integer("attempts").notNull().default(0),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
});

export const recoveryCodes = pgTable("recovery_codes", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  codeHash: text("code_hash").notNull(),
  usedAt: timestamp("used_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
}, t => [index("recovery_codes_user_idx").on(t.userId)]);

export const clients = pgTable("clients", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: orgRef(),
  name: text("name").notNull(),
  contactName: text("contact_name"),
  contactEmail: text("contact_email"),
  ...timestamps
}, t => [index("clients_org_idx").on(t.organizationId)]);

export const authorizations = pgTable("authorizations", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: orgRef(),
  clientId: uuid("client_id").references(() => clients.id, { onDelete: "set null" }),
  reference: text("reference").notNull(),
  hostnames: text("hostnames").array().notNull().default(sql`'{}'::text[]`),
  validFrom: timestamp("valid_from", { withTimezone: true }),
  validUntil: timestamp("valid_until", { withTimezone: true }),
  emergencyContact: text("emergency_contact"),
  exclusions: text("exclusions"),
  // Hostnames fora do escopo mesmo que casem com um curinga de `hostnames`.
  excludedHostnames: text("excluded_hostnames").array().notNull().default(sql`'{}'::text[]`),
  // pending → approved (por outra pessoa com scope:approve) → revoked. Só "approved" dentro da validade libera avaliações.
  status: authorizationStatusEnum("status").notNull().default("pending"),
  createdBy: uuid("created_by").references(() => users.id, { onDelete: "set null" }),
  approvedBy: uuid("approved_by").references(() => users.id, { onDelete: "set null" }),
  approvedAt: timestamp("approved_at", { withTimezone: true }),
  revokedBy: uuid("revoked_by").references(() => users.id, { onDelete: "set null" }),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
  revokeReason: text("revoke_reason"),
  // Quando o aviso de vencimento próximo foi enviado (uma vez por autorização).
  expiryNotifiedAt: timestamp("expiry_notified_at", { withTimezone: true }),
  ...timestamps
}, t => [index("authorizations_org_idx").on(t.organizationId)]);

export const assets = pgTable("assets", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: orgRef(),
  clientId: uuid("client_id").references(() => clients.id, { onDelete: "set null" }),
  authorizationId: uuid("authorization_id").references(() => authorizations.id, { onDelete: "set null" }),
  name: text("name").notNull(),
  url: text("url").notNull(),
  kind: assetKindEnum("kind").notNull(),
  owner: text("owner").notNull(),
  // Cópia da referência da autorização no momento do cadastro (aparece nos relatórios).
  authorizationRef: text("authorization_ref").notNull(),
  // Reavaliação periódica: null = só manual. O worker enfileira quando next_assessment_at chega.
  scheduleIntervalDays: integer("schedule_interval_days"),
  nextAssessmentAt: timestamp("next_assessment_at", { withTimezone: true }),
  ...timestamps
}, t => [
  index("assets_org_created_idx").on(t.organizationId, t.createdAt),
  index("assets_next_assessment_idx").on(t.nextAssessmentAt).where(sql`${t.nextAssessmentAt} is not null`)
]);

// Cada linha é ao mesmo tempo o job da fila (queued → running) e o registro da execução (completed | failed).
export const assessments = pgTable("assessments", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: orgRef(),
  assetId: uuid("asset_id").notNull().references(() => assets.id, { onDelete: "cascade" }),
  status: assessmentStatusEnum("status").notNull(),
  trigger: assessmentTriggerEnum("trigger").notNull().default("manual"),
  requestedBy: uuid("requested_by").references(() => users.id, { onDelete: "set null" }),
  method: text("method").notNull(),
  error: text("error"),
  attempts: integer("attempts").notNull().default(0),
  // Não processar antes deste instante (novas tentativas usam espera crescente).
  runAfter: timestamp("run_after", { withTimezone: true }).notNull().defaultNow(),
  // Quando um worker pegou o job; running com locked_at antigo é considerado travado e volta para a fila.
  lockedAt: timestamp("locked_at", { withTimezone: true }),
  summary: jsonb("summary").$type<{ observed: number; created: number; reopened: number; resolved: number }>(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  startedAt: timestamp("started_at", { withTimezone: true }),
  finishedAt: timestamp("finished_at", { withTimezone: true })
}, t => [
  index("assessments_org_asset_idx").on(t.organizationId, t.assetId, t.startedAt),
  index("assessments_org_created_idx").on(t.organizationId, t.createdAt),
  index("assessments_queue_idx").on(t.runAfter).where(sql`${t.status} = 'queued'`),
  // No máximo uma avaliação pendente ou em execução por ativo.
  uniqueIndex("assessments_active_asset_idx").on(t.assetId).where(sql`${t.status} in ('queued', 'running')`)
]);

export const findings = pgTable("findings", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: orgRef(),
  assetId: uuid("asset_id").notNull().references(() => assets.id, { onDelete: "cascade" }),
  assessmentId: uuid("assessment_id").references(() => assessments.id, { onDelete: "cascade" }),
  title: text("title").notNull(),
  severity: severityEnum("severity").notNull(),
  category: text("category").notNull(),
  description: text("description").notNull(),
  evidence: text("evidence").notNull(),
  recommendation: text("recommendation").notNull(),
  references: jsonb("references").$type<string[]>().notNull().default([]),
  // Identifica o mesmo problema entre avaliações do ativo (categoria + título): um achado por problema, não por execução.
  fingerprint: text("fingerprint").notNull(),
  status: findingStatusEnum("status").notNull().default("open"),
  statusReason: text("status_reason"),
  statusChangedAt: timestamp("status_changed_at", { withTimezone: true }),
  statusChangedBy: uuid("status_changed_by").references(() => users.id, { onDelete: "set null" }),
  // Aceite de risco com prazo: vencido, o achado volta a "open".
  acceptedUntil: timestamp("accepted_until", { withTimezone: true }),
  discoveredAt: timestamp("discovered_at", { withTimezone: true }).notNull().defaultNow(),
  lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
  lastAssessmentId: uuid("last_assessment_id").references(() => assessments.id, { onDelete: "set null" })
}, t => [
  index("findings_org_discovered_idx").on(t.organizationId, t.discoveredAt),
  index("findings_assessment_idx").on(t.assessmentId),
  uniqueIndex("findings_asset_fingerprint_idx").on(t.organizationId, t.assetId, t.fingerprint)
]);

// Quais achados cada execução observou (a execução é um retrato; o achado é o problema ao longo do tempo).
export const assessmentFindings = pgTable("assessment_findings", {
  organizationId: orgRef(),
  assessmentId: uuid("assessment_id").notNull().references(() => assessments.id, { onDelete: "cascade" }),
  findingId: uuid("finding_id").notNull().references(() => findings.id, { onDelete: "cascade" }),
  evidence: text("evidence").notNull()
}, t => [primaryKey({ columns: [t.assessmentId, t.findingId] }), index("assessment_findings_finding_idx").on(t.findingId)]);

// Histórico de triagem de cada achado (somente inserção).
export const findingEvents = pgTable("finding_events", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: orgRef(),
  findingId: uuid("finding_id").notNull().references(() => findings.id, { onDelete: "cascade" }),
  actorUserId: uuid("actor_user_id").references(() => users.id, { onDelete: "set null" }),
  fromStatus: findingStatusEnum("from_status"),
  toStatus: findingStatusEnum("to_status").notNull(),
  reason: text("reason"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
}, t => [index("finding_events_finding_idx").on(t.findingId, t.createdAt)]);

// Trilha de auditoria somente de inserção; o repositório não expõe update/delete.
export const auditLog = pgTable("audit_log", {
  id: uuid("id").primaryKey().defaultRandom(),
  // Sequência monotônica: ordena eventos gravados no mesmo milissegundo.
  seq: bigint("seq", { mode: "number" }).generatedAlwaysAsIdentity().notNull(),
  organizationId: orgRef(),
  actorUserId: uuid("actor_user_id").references(() => users.id, { onDelete: "set null" }),
  action: text("action").notNull(),
  targetType: text("target_type").notNull(),
  targetId: text("target_id"),
  metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull().default({}),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
}, t => [index("audit_log_org_created_idx").on(t.organizationId, t.createdAt)]);

// Provedor OIDC da organização (Google Workspace, Entra ID, Okta…). client_secret cifrado (src/lib/crypto.ts).
export const ssoConnections = pgTable("sso_connections", {
  organizationId: uuid("organization_id").primaryKey().references(() => organizations.id, { onDelete: "cascade" }),
  issuer: text("issuer").notNull(),
  clientId: text("client_id").notNull(),
  clientSecret: text("client_secret").notNull(),
  allowedDomains: jsonb("allowed_domains").$type<string[]>().notNull(),
  enabled: boolean("enabled").notNull().default(false),
  // Só Owners continuam entrando com senha (acesso de emergência).
  enforced: boolean("enforced").notNull().default(false),
  // Papel dado a quem entra pela primeira vez via SSO; null = só usuários já cadastrados.
  jitRole: roleEnum("jit_role"),
  ...timestamps
});

// Vínculo estável usuário ↔ (issuer, sub), para não depender só do e-mail.
export const ssoIdentities = pgTable("sso_identities", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  organizationId: orgRef(),
  issuer: text("issuer").notNull(),
  subject: text("subject").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
}, t => [uniqueIndex("sso_identities_issuer_subject_idx").on(t.issuer, t.subject)]);

// Login SSO em andamento; id = SHA-256 do state (que também fica num cookie do navegador).
export const ssoRequests = pgTable("sso_requests", {
  id: text("id").primaryKey(),
  organizationId: orgRef(),
  nonce: text("nonce").notNull(),
  codeVerifier: text("code_verifier").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
});

// Avisos dentro da aplicação, um por destinatário (lidos individualmente).
export const notifications = pgTable("notifications", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: orgRef(),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  kind: text("kind").notNull(),
  title: text("title").notNull(),
  body: text("body").notNull().default(""),
  link: text("link"),
  readAt: timestamp("read_at", { withTimezone: true }),
  // Cópia por e-mail: null = não enviar; pending → sent | failed | skipped. O worker envia com FOR UPDATE SKIP LOCKED.
  emailStatus: text("email_status"),
  emailAttempts: integer("email_attempts").notNull().default(0),
  emailNextAttemptAt: timestamp("email_next_attempt_at", { withTimezone: true }),
  emailLockedAt: timestamp("email_locked_at", { withTimezone: true }),
  emailError: text("email_error"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
}, t => [
  index("notifications_user_idx").on(t.organizationId, t.userId, t.createdAt),
  index("notifications_email_queue_idx").on(t.emailNextAttemptAt).where(sql`${t.emailStatus} = 'pending'`)
]);

// Token de API pessoal: age como o usuário, com papel limitado (Leitor ou Analista). O token nunca é gravado, só o SHA-256.
export const apiTokens = pgTable("api_tokens", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: orgRef(),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  tokenHash: text("token_hash").notNull(),
  // Início do token (snt_xxxxxxxx) para identificá-lo na interface.
  prefix: text("prefix").notNull(),
  role: roleEnum("role").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
  lastUsedIp: text("last_used_ip"),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
}, t => [uniqueIndex("api_tokens_hash_idx").on(t.tokenHash), index("api_tokens_org_user_idx").on(t.organizationId, t.userId)]);

export const webhookDeliveryStatusEnum = pgEnum("webhook_delivery_status", ["pending", "delivered", "failed"]);

// Destino de eventos da organização. O segredo de assinatura é cifrado (src/lib/crypto.ts).
export const webhooks = pgTable("webhooks", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: orgRef(),
  name: text("name").notNull(),
  url: text("url").notNull(),
  secret: text("secret").notNull(),
  events: text("events").array().notNull(),
  enabled: boolean("enabled").notNull().default(true),
  // Entregas que esgotaram as tentativas em sequência; ao atingir o limite o webhook é desligado.
  consecutiveFailures: integer("consecutive_failures").notNull().default(0),
  disabledReason: text("disabled_reason"),
  createdBy: uuid("created_by").references(() => users.id, { onDelete: "set null" }),
  ...timestamps
}, t => [index("webhooks_org_idx").on(t.organizationId)]);

// Fila de entregas: uma linha por (evento, webhook). O worker envia com FOR UPDATE SKIP LOCKED, como na fila de avaliações.
export const webhookDeliveries = pgTable("webhook_deliveries", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: orgRef(),
  webhookId: uuid("webhook_id").notNull().references(() => webhooks.id, { onDelete: "cascade" }),
  // Mesmo id para todos os webhooks que recebem o evento; o destinatário usa para descartar duplicatas.
  eventId: uuid("event_id").notNull(),
  event: text("event").notNull(),
  payload: jsonb("payload").$type<Record<string, unknown>>().notNull(),
  status: webhookDeliveryStatusEnum("status").notNull().default("pending"),
  attempts: integer("attempts").notNull().default(0),
  nextAttemptAt: timestamp("next_attempt_at", { withTimezone: true }).notNull().defaultNow(),
  lockedAt: timestamp("locked_at", { withTimezone: true }),
  responseStatus: integer("response_status"),
  lastError: text("last_error"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  deliveredAt: timestamp("delivered_at", { withTimezone: true })
}, t => [
  index("webhook_deliveries_queue_idx").on(t.nextAttemptAt).where(sql`${t.status} = 'pending'`),
  index("webhook_deliveries_webhook_idx").on(t.webhookId, t.createdAt)
]);
