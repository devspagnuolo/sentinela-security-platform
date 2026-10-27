import { and, asc, count, desc, eq, inArray, isNotNull, isNull, lt, lte, ne, or, sql, type SQL } from "drizzle-orm";
import { z } from "zod";
import type { Role } from "@/lib/auth/rbac";
import { logger } from "@/lib/logger";
import { mailSettings, notificationEmail, smtpTransport, type MailTransport } from "@/lib/mail";
import type { Notification } from "@/lib/types";
import type { Database } from "./client";
import { memberships, notifications, users } from "./schema";

/** Quem recebe cada tipo de aviso: operação (quem avalia e faz triagem) ou gestão (quem aprova). */
export type Audience = "operators" | "managers";
const AUDIENCE_ROLES: Record<Audience, Role[]> = { operators: ["owner", "admin", "analyst"], managers: ["owner", "admin"] };

export type NewNotification = { kind: string; title: string; body?: string; link?: string };
export const NOTIFICATION_RETENTION_DAYS = 90;

const isUuid = (value: string) => z.uuid().safeParse(value).success;

/** Grava o aviso para cada membro ativo da organização no público indicado (ou para usuários específicos); com SMTP configurado, enfileira a cópia por e-mail de quem a quer. */
export async function notify(db: Database, organizationId: string, to: { audience: Audience; exclude?: string | null } | { userIds: string[] }, n: NewNotification) {
  const conditions: SQL[] = [eq(memberships.organizationId, organizationId), eq(users.disabled, false)];
  if ("userIds" in to) {
    if (!to.userIds.length) return 0;
    conditions.push(inArray(memberships.userId, to.userIds));
  } else {
    conditions.push(inArray(memberships.role, AUDIENCE_ROLES[to.audience]));
    if (to.exclude) conditions.push(ne(memberships.userId, to.exclude));
  }
  const recipients = await db.select({ userId: memberships.userId, email: users.emailNotifications }).from(memberships).innerJoin(users, eq(users.id, memberships.userId)).where(and(...conditions));
  if (!recipients.length) return 0;
  const mail = mailSettings().enabled;
  await db.insert(notifications).values(recipients.map(r => ({
    organizationId, userId: r.userId, kind: n.kind, title: n.title.slice(0, 200), body: (n.body ?? "").slice(0, 1000), link: n.link ?? null,
    ...(mail && r.email && { emailStatus: "pending", emailNextAttemptAt: new Date() })
  })));
  return recipients.length;
}

/** Caixa de avisos de um usuário dentro de uma organização. */
export function notificationRepository(db: Database, organizationId: string, userId: string) {
  const mine = and(eq(notifications.organizationId, organizationId), eq(notifications.userId, userId));
  return {
    async list(limit = 50): Promise<Notification[]> {
      const rows = await db.select().from(notifications).where(mine).orderBy(desc(notifications.createdAt)).limit(Math.min(Math.max(limit, 1), 200));
      return rows.map(r => ({ id: r.id, kind: r.kind, title: r.title, body: r.body, link: r.link, readAt: r.readAt?.toISOString() ?? null, createdAt: r.createdAt.toISOString() }));
    },
    async unreadCount() {
      const [row] = await db.select({ n: count() }).from(notifications).where(and(mine, isNull(notifications.readAt)));
      return Number(row?.n ?? 0);
    },
    /** Marca como lidos os avisos informados (ou todos, sem ids). */
    async markRead(ids?: string[], now = new Date()) {
      const conditions = [mine, isNull(notifications.readAt)];
      if (ids) {
        const valid = ids.filter(isUuid);
        if (!valid.length) return 0;
        conditions.push(inArray(notifications.id, valid));
      }
      return (await db.update(notifications).set({ readAt: now }).where(and(...conditions)).returning({ id: notifications.id })).length;
    }
  };
}

/** Remove avisos lidos há mais de NOTIFICATION_RETENTION_DAYS dias. */
export async function pruneNotifications(db: Database, now = new Date()) {
  const before = new Date(now.getTime() - NOTIFICATION_RETENTION_DAYS * 86_400_000);
  await db.delete(notifications).where(and(isNotNull(notifications.readAt), lt(notifications.readAt, before)));
}

// ---- Cópia por e-mail (worker) --------------------------------------------------------

/** Espera antes de cada nova tentativa de e-mail (minutos). Depois da última, o envio falha. */
export const EMAIL_RETRY_MINUTES = [1, 10, 60];
const EMAIL_STALE_LOCK_MS = 2 * 60_000;

/** Pega o próximo e-mail pendente e o marca como em envio, atomicamente entre instâncias. */
export async function claimEmail(db: Database, now = new Date()) {
  const next = db.select({ id: notifications.id }).from(notifications)
    .where(and(eq(notifications.emailStatus, "pending"), lte(notifications.emailNextAttemptAt, now),
      or(isNull(notifications.emailLockedAt), lt(notifications.emailLockedAt, new Date(now.getTime() - EMAIL_STALE_LOCK_MS)))))
    .orderBy(asc(notifications.emailNextAttemptAt)).limit(1).for("update", { skipLocked: true });
  const [row] = await db.update(notifications).set({ emailLockedAt: now, emailAttempts: sql`${notifications.emailAttempts} + 1` })
    .where(and(eq(notifications.id, sql`(${next})`), eq(notifications.emailStatus, "pending"))).returning();
  return row;
}

export type EmailDeps = { transport?: MailTransport; now?: () => Date };

/** Envia os e-mails pendentes. Quem desativou a preferência ou a conta depois do aviso não recebe. */
export async function sendPendingEmails(db: Database, deps: EmailDeps = {}) {
  const now = () => deps.now?.() ?? new Date();
  let sent = 0;
  for (let row = await claimEmail(db, now()); row; row = await claimEmail(db, now())) {
    const finish = (set: Partial<typeof notifications.$inferInsert>) => db.update(notifications).set({ emailLockedAt: null, ...set }).where(eq(notifications.id, row!.id));
    const [user] = await db.select({ email: users.email, name: users.name, disabled: users.disabled, wants: users.emailNotifications }).from(users).where(eq(users.id, row.userId));
    if (!user || user.disabled || !user.wants) { await finish({ emailStatus: "skipped" }); continue; }
    try {
      await (deps.transport ?? smtpTransport())(notificationEmail(row, user));
      await finish({ emailStatus: "sent", emailError: null });
      sent++;
    } catch (error) {
      const message = (error instanceof Error ? error.message : "Falha no envio.").slice(0, 300);
      const retry = EMAIL_RETRY_MINUTES[row.emailAttempts - 1];
      await finish(retry === undefined ? { emailStatus: "failed", emailError: message } : { emailError: message, emailNextAttemptAt: new Date(now().getTime() + retry * 60_000) });
      logger.warn("notification.email_failed", { notificationId: row.id, attempts: row.emailAttempts, error: message });
    }
  }
  return sent;
}
