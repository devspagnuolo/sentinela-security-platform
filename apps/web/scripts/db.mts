// Uso: tsx scripts/db.mts migrate | seed — requer DATABASE_URL.
import path from "node:path";
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { Pool } from "pg";
import type { Database } from "../src/db/client";
import * as schema from "../src/db/schema";
import { seedDemo } from "../src/db/seed";

const command = process.argv[2];
if (!process.env.DATABASE_URL) { console.error("Defina DATABASE_URL."); process.exit(1); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const db = drizzle(pool, { schema });
try {
  if (command === "migrate") {
    await migrate(db, { migrationsFolder: path.join(import.meta.dirname, "..", "drizzle") });
    console.log("Migrações aplicadas.");
  } else if (command === "seed") {
    console.log("Organização demonstrativa:", await seedDemo(db as unknown as Database));
  } else {
    console.error("Comando: migrate | seed"); process.exitCode = 1;
  }
} finally { await pool.end(); }
