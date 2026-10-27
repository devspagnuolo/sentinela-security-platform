import { sql } from "drizzle-orm";
import { bigint, boolean, index, integer, jsonb, pgEnum, pgTable, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";

// Toda tabela de negócio carrega organization_id: o isolamento entre organizações
// é garantido na camada de repositório (src/db/repository.ts), que sempre filtra por ele.

export const roleEnum = pgEnum("role", ["owner", "admin", "analyst", "viewer"]);
export const assetKindEnum = pgEnum("asset_kind", ["Web application", "API"]);
export const severityEnum = pgEnum("severity", ["critical", "high", "medium", "low", "info"]);
export const assessmentStatusEnum = pgEnum("assessment_status", ["queued", "running", "completed", "failed"]);
export const findingStatusEnum = pgEnum("finding_status", ["open", "accepted", "fixed", "false_positive"]);

const timestamps = {
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date())
};
const orgRef = () => uuid("organization_id").notNull().references(() => organizations.id, { onDelete: "cascade" });

export const organizations = pgTable("organizations", {
  id: uuid("id").primaryKey().defaultRandom(),
  slug: text("slug").notNull().unique(),
  name: text("name").notNull(),
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
  ip: text("ip"),
  userAgent: text("user_agent")
}, t => [index("sessions_user_idx").on(t.userId), index("sessions_expires_idx").on(t.expiresAt)]);

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
  authorizationRef: text("authorization_ref").notNull(),
  approved: boolean("approved").notNull().default(false),
  ...timestamps
}, t => [index("assets_org_created_idx").on(t.organizationId, t.createdAt)]);

export const assessments = pgTable("assessments", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: orgRef(),
  assetId: uuid("asset_id").notNull().references(() => assets.id, { onDelete: "cascade" }),
  status: assessmentStatusEnum("status").notNull(),
  method: text("method").notNull(),
  error: text("error"),
  startedAt: timestamp("started_at", { withTimezone: true }).notNull().defaultNow(),
  finishedAt: timestamp("finished_at", { withTimezone: true })
}, t => [index("assessments_org_asset_idx").on(t.organizationId, t.assetId, t.startedAt)]);

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
  status: findingStatusEnum("status").notNull().default("open"),
  discoveredAt: timestamp("discovered_at", { withTimezone: true }).notNull().defaultNow()
}, t => [index("findings_org_discovered_idx").on(t.organizationId, t.discoveredAt), index("findings_assessment_idx").on(t.assessmentId)]);

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
