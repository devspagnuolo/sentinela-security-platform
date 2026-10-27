type Level = "debug" | "info" | "warn" | "error";
const ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

/** Remove dados que nunca devem ir para log (senhas, tokens, segredos). */
const SENSITIVE = /pass(word)?|secret|token|cookie|authorization|code_verifier/i;
function scrub(value: unknown, depth = 0): unknown {
  if (value instanceof Error) return { name: value.name, message: value.message, ...(process.env.NODE_ENV !== "production" && { stack: value.stack }) };
  if (!value || typeof value !== "object" || depth > 3) return value;
  if (Array.isArray(value)) return value.slice(0, 20).map(v => scrub(v, depth + 1));
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, SENSITIVE.test(k) ? "[redacted]" : scrub(v, depth + 1)]));
}

/**
 * Log estruturado em JSON (uma linha por evento), pronto para `docker logs`,
 * journald ou um coletor. Nível mínimo em SENTINELA_LOG_LEVEL (padrão info).
 */
export function log(level: Level, message: string, fields: Record<string, unknown> = {}) {
  const min = ORDER[(process.env.SENTINELA_LOG_LEVEL as Level) ?? "info"] ?? ORDER.info;
  if (ORDER[level] < min || process.env.NODE_ENV === "test") return;
  const line = JSON.stringify({ time: new Date().toISOString(), level, msg: message, ...(scrub(fields) as object) });
  if (level === "error" || level === "warn") console.error(line); else console.log(line);
}

export const logger = {
  debug: (message: string, fields?: Record<string, unknown>) => log("debug", message, fields),
  info: (message: string, fields?: Record<string, unknown>) => log("info", message, fields),
  warn: (message: string, fields?: Record<string, unknown>) => log("warn", message, fields),
  error: (message: string, fields?: Record<string, unknown>) => log("error", message, fields)
};
