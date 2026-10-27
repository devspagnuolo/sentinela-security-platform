import { eq } from "drizzle-orm";
import { getDb } from "@/db/client";
import { tenantRepository, type TenantRepository } from "@/db/repository";
import { organizations } from "@/db/schema";
import { DEFAULT_ORG_SLUG } from "@/db/seed";

/**
 * Resolve a organização da requisição. Até a fase 2 (login e RBAC) existe uma
 * única organização, definida por SENTINELA_DEFAULT_ORG; depois, ela virá da sessão.
 */
export async function requestRepository(): Promise<TenantRepository> {
  const db = await getDb();
  const slug = process.env.SENTINELA_DEFAULT_ORG ?? DEFAULT_ORG_SLUG;
  let [org] = await db.select({ id: organizations.id }).from(organizations).where(eq(organizations.slug, slug));
  if (!org) [org] = await db.insert(organizations).values({ slug, name: "Minha consultoria" }).onConflictDoNothing().returning({ id: organizations.id });
  if (!org) [org] = await db.select({ id: organizations.id }).from(organizations).where(eq(organizations.slug, slug));
  return tenantRepository(db, org.id);
}
