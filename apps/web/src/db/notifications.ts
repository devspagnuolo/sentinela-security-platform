import { and, count, desc, eq, inArray, isNotNull, isNull, lt, ne, type SQL } from "drizzle-orm";
import { z } from "zod";
import type { Role } from "@/lib/auth/rbac";
import type { Notification } from "@/lib/types";
import type { Database } from "./client";
import { memberships, notifications, users } from "./schema";

/** Quem recebe cada tipo de aviso: operação (quem avalia e faz triagem) ou gestão (quem aprova). */
export type Audience = "operators" | "managers";
const AUDIENCE_ROLES: Record<Audience, Role[]> = { operators: ["owner", "admin", "analyst"], managers: ["owner", "admin"] };

export type NewNotification = { kind: string; title: string; body?: string; link?: string };
export const NOTIFICATION_RETENTION_DAYS = 90;

const isUuid = (value: string) => z.uuid().safeParse(value).success;

/** Grava o aviso para cada membro ativo da organização no público indicado (ou para usuários específicos). */
export async function notify(db: Database, organizationId: string, to: { audience: Audience; exclude?: string | null } | { userIds: string[] }, n: NewNotification) {
  const conditions: SQL[] = [eq(memberships.organizationId, organizationId), eq(users.disabled, false)];
  if ("userIds" in to) {
    if (!to.userIds.length) return 0;
    conditions.push(inArray(memberships.userId, to.userIds));
  } else {
    conditions.push(inArray(memberships.role, AUDIENCE_ROLES[to.audience]));
    if (to.exclude) conditions.push(ne(memberships.userId, to.exclude));
  }
  const recipients = await db.select({ userId: memberships.userId }).from(memberships).innerJoin(users, eq(users.id, memberships.userId)).where(and(...conditions));
  if (!recipients.length) return 0;
  await db.insert(notifications).values(recipients.map(r => ({ organizationId, userId: r.userId, kind: n.kind, title: n.title.slice(0, 200), body: (n.body ?? "").slice(0, 1000), link: n.link ?? null })));
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
