import path from "node:path";
import type { PgDatabase, PgQueryResultHKT } from "drizzle-orm/pg-core";
import * as schema from "./schema";
import { seedDemo } from "./seed";

export type Database = PgDatabase<PgQueryResultHKT, typeof schema>;

const migrationsFolder = () => process.env.SENTINELA_MIGRATIONS_DIR ?? path.join(process.cwd(), "drizzle");

/**
 * Com DATABASE_URL, conecta ao PostgreSQL (produção). Sem ela, usa PGlite
 * (PostgreSQL embutido) em memória ou em SENTINELA_PGLITE_DIR, com dados
 * demonstrativos — apenas para desenvolvimento e testes.
 */
export async function createDatabase(env: NodeJS.ProcessEnv = process.env): Promise<Database> {
  if (env.DATABASE_URL) {
    const [{ drizzle }, { migrate }, { Pool }] = await Promise.all([import("drizzle-orm/node-postgres"), import("drizzle-orm/node-postgres/migrator"), import("pg")]);
    const pool = new Pool({ connectionString: env.DATABASE_URL, max: Number(env.DATABASE_POOL_MAX ?? 10) });
    const db = drizzle(pool, { schema });
    if (env.SENTINELA_AUTO_MIGRATE === "1") await migrate(db, { migrationsFolder: migrationsFolder() });
    return db as unknown as Database;
  }
  if (env.NODE_ENV === "production" && env.SENTINELA_ALLOW_EMBEDDED_DB !== "1") throw new Error("DATABASE_URL é obrigatória em produção.");
  const [{ drizzle }, { migrate }, { PGlite }] = await Promise.all([import("drizzle-orm/pglite"), import("drizzle-orm/pglite/migrator"), import("@electric-sql/pglite")]);
  const db = drizzle(new PGlite(env.SENTINELA_PGLITE_DIR), { schema });
  await migrate(db, { migrationsFolder: migrationsFolder() });
  if (env.SENTINELA_SEED_DEMO !== "0") await seedDemo(db as unknown as Database);
  return db as unknown as Database;
}

const g = globalThis as typeof globalThis & { sentinelaDb?: Promise<Database> };

export function getDb(): Promise<Database> {
  g.sentinelaDb ??= createDatabase().catch(error => { g.sentinelaDb = undefined; throw error; });
  return g.sentinelaDb;
}
