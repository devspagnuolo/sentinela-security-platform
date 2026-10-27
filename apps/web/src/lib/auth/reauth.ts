import { eq } from "drizzle-orm";
import type { Database } from "@/db/client";
import { users } from "@/db/schema";
import { verifyPassword } from "./password";

/** Confirma a senha atual antes de operações sensíveis da própria conta. */
export async function confirmPassword(db: Database, userId: string, password: string) {
  const [row] = await db.select({ passwordHash: users.passwordHash }).from(users).where(eq(users.id, userId));
  return Boolean(row?.passwordHash && (await verifyPassword(password, row.passwordHash)));
}
