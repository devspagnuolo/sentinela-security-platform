import { getDb } from "@/db/client";
import { organizations } from "@/db/schema";
import { memberRepository } from "@/db/users";
import type { Role } from "@/lib/auth/rbac";
import { createSession } from "@/lib/auth/session";
import { sessionCookieName } from "@/lib/auth/http";

export const ORIGIN = "http://localhost";
export const TEST_PASSWORD = "correct-horse-battery-staple";

let counter = 0;

/** Cria organização (ou reutiliza), usuário com papel e sessão; devolve o cookie pronto. */
export async function signIn(role: Role, organizationId?: string) {
  const db = await getDb();
  const orgId = organizationId ?? (await db.insert(organizations).values({ slug: `org-${Date.now()}-${++counter}`, name: "Org teste" }).returning())[0].id;
  const member = await memberRepository(db, orgId).create({ email: `${role}-${Date.now()}-${++counter}@example.com`, name: `Usuário ${role}`, role, password: TEST_PASSWORD });
  const { token } = await createSession(db, { userId: member.id, organizationId: orgId });
  return { organizationId: orgId, user: member, cookie: `${sessionCookieName()}=${token}`, token };
}

export function request(path: string, init: { method?: string; cookie?: string; body?: unknown; origin?: string | null } = {}) {
  const headers = new Headers({ "Content-Type": "application/json" });
  if (init.cookie) headers.set("cookie", init.cookie);
  const method = init.method ?? (init.body === undefined ? "GET" : "POST");
  if (init.origin !== null && method !== "GET") headers.set("origin", init.origin ?? ORIGIN);
  return new Request(`${ORIGIN}${path}`, { method, headers, body: init.body === undefined ? undefined : typeof init.body === "string" ? init.body : JSON.stringify(init.body) });
}

