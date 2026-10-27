import type { Instrumentation } from "next";

/** Executado uma vez ao iniciar o servidor: valida a configuração e aplica migrações antes do primeiro acesso. */
export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  const { logger } = await import("@/lib/logger");
  if (process.env.NODE_ENV === "production" && !process.env.SENTINELA_PUBLIC_ORIGIN) logger.warn("config.public_origin_missing", { hint: "Defina SENTINELA_PUBLIC_ORIGIN com a URL pública (CSRF e retorno do SSO)." });
  if (process.env.DATABASE_URL) {
    const { getDb } = await import("@/db/client");
    try {
      await getDb();
      logger.info("server.started", { database: "postgres", autoMigrate: process.env.SENTINELA_AUTO_MIGRATE === "1" });
    } catch (error) {
      logger.error("server.database_init_failed", { error });
    }
  }
}

export const onRequestError: Instrumentation.onRequestError = async (error, request, context) => {
  const { logger } = await import("@/lib/logger");
  logger.error("request.failed", { error, method: request.method, path: request.path.split("?")[0], route: context.routePath, routeType: context.routeType });
};
