import { and, asc, count, eq, sql } from "drizzle-orm";
import type { Role } from "@/lib/auth/rbac";
import { hashPassword } from "@/lib/auth/password";
import type { Database } from "./client";
import { memberships, users } from "./schema";

export type Member = { id: string; email: string; name: string; role: Role; disabled: boolean; mfaEnabled: boolean; lastLoginAt: string | null; createdAt: string };

const normalizeEmail = (email: string) => email.trim().toLowerCase();

export async function findUserByEmail(db: Database, email: string) {
  const [user] = await db.select().from(users).where(sql`lower(${users.email}) = ${normalizeEmail(email)}`);
  return user;
}

/** Primeira organização do usuário (instalação privada: normalmente a única). */
export async function primaryMembership(db: Database, userId: string) {
  const [membership] = await db.select().from(memberships).where(eq(memberships.userId, userId)).orderBy(asc(memberships.createdAt)).limit(1);
  return membership;
}

const memberColumns = { id: users.id, email: users.email, name: users.name, role: memberships.role, disabled: users.disabled, totpEnabledAt: users.totpEnabledAt, lastLoginAt: users.lastLoginAt, createdAt: users.createdAt };
const toMember = ({ totpEnabledAt, ...row }: { id: string; email: string; name: string; role: Role; disabled: boolean; totpEnabledAt: Date | null; lastLoginAt: Date | null; createdAt: Date }): Member => ({ ...row, mfaEnabled: Boolean(totpEnabledAt), lastLoginAt: row.lastLoginAt?.toISOString() ?? null, createdAt: row.createdAt.toISOString() });

/** Operações de membros sempre restritas a uma organização. */
export function memberRepository(db: Database, organizationId: string) {
  return {
    async list(): Promise<Member[]> {
      const rows = await db.select(memberColumns).from(memberships).innerJoin(users, eq(users.id, memberships.userId)).where(eq(memberships.organizationId, organizationId)).orderBy(asc(users.name));
      return rows.map(toMember);
    },

    async get(userId: string): Promise<Member | undefined> {
      const [row] = await db.select(memberColumns).from(memberships).innerJoin(users, eq(users.id, memberships.userId)).where(and(eq(memberships.organizationId, organizationId), eq(memberships.userId, userId)));
      return row && toMember(row);
    },

    async create(input: { email: string; name: string; role: Role; password: string }): Promise<Member> {
      if (await findUserByEmail(db, input.email)) throw new Error("Já existe um usuário com este e-mail.");
      const passwordHash = await hashPassword(input.password);
      return db.transaction(async tx => {
        const [user] = await tx.insert(users).values({ email: normalizeEmail(input.email), name: input.name.trim(), passwordHash, passwordChangedAt: new Date() }).returning();
        await tx.insert(memberships).values({ organizationId, userId: user.id, role: input.role });
        return toMember({ ...user, role: input.role });
      });
    },

    async update(userId: string, changes: { role?: Role; disabled?: boolean; name?: string }) {
      if (changes.role) await db.update(memberships).set({ role: changes.role }).where(and(eq(memberships.organizationId, organizationId), eq(memberships.userId, userId)));
      if (changes.disabled !== undefined || changes.name) await db.update(users).set({ ...(changes.disabled !== undefined && { disabled: changes.disabled }), ...(changes.name && { name: changes.name.trim() }) }).where(eq(users.id, userId));
      return this.get(userId);
    },

    async activeOwnerCount(): Promise<number> {
      const [row] = await db.select({ n: count() }).from(memberships).innerJoin(users, eq(users.id, memberships.userId)).where(and(eq(memberships.organizationId, organizationId), eq(memberships.role, "owner"), eq(users.disabled, false)));
      return row?.n ?? 0;
    }
  };
}
