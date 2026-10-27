// Uso (requer DATABASE_URL):
//   tsx scripts/db.mts migrate
//   tsx scripts/db.mts seed                          (dados demo; Owner demo só com SENTINELA_DEMO_PASSWORD)
//   tsx scripts/db.mts create-owner <email> "<nome>" (senha em SENTINELA_OWNER_PASSWORD ou gerada)
import { randomBytes } from "node:crypto";
import path from "node:path";
import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { Pool } from "pg";
import type { Database } from "../src/db/client";
import * as schema from "../src/db/schema";
import { DEFAULT_ORG_SLUG, seedDemo } from "../src/db/seed";
import { memberRepository } from "../src/db/users";
import { passwordPolicyError } from "../src/lib/auth/password";

const [command, ...args] = process.argv.slice(2);
if (!process.env.DATABASE_URL) { console.error("Defina DATABASE_URL."); process.exit(1); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const db = drizzle(pool, { schema }) as unknown as Database;

async function createOwner(email: string | undefined, name: string | undefined) {
  if (!email || !name) throw new Error('Uso: create-owner <email> "<nome>"');
  const slug = process.env.SENTINELA_DEFAULT_ORG ?? DEFAULT_ORG_SLUG;
  let [org] = await db.select().from(schema.organizations).where(eq(schema.organizations.slug, slug));
  org ??= (await db.insert(schema.organizations).values({ slug, name: process.env.SENTINELA_ORG_NAME ?? "Minha consultoria" }).returning())[0];
  const generated = !process.env.SENTINELA_OWNER_PASSWORD;
  const password = process.env.SENTINELA_OWNER_PASSWORD ?? randomBytes(18).toString("base64url");
  const policy = passwordPolicyError(password, { email });
  if (policy) throw new Error(policy);
  const owner = await memberRepository(db, org.id).create({ email, name, role: "owner", password });
  console.log(`Owner criado: ${owner.email} na organização "${org.name}".`);
  if (generated) console.log(`Senha gerada (exibida só agora; troque após o primeiro login): ${password}`);
}

try {
  if (command === "migrate") {
    await migrate(db, { migrationsFolder: path.join(import.meta.dirname, "..", "drizzle") });
    console.log("Migrações aplicadas.");
  } else if (command === "seed") {
    console.log("Organização demonstrativa:", await seedDemo(db, { ownerPassword: process.env.SENTINELA_DEMO_PASSWORD }));
  } else if (command === "create-owner") {
    await createOwner(args[0], args[1]);
  } else {
    console.error("Comandos: migrate | seed | create-owner"); process.exitCode = 1;
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : error); process.exitCode = 1;
} finally { await pool.end(); }
