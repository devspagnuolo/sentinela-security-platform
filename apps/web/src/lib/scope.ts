/**
 * Regras de escopo autorizado. Funções puras: a mesma lógica vale no cadastro
 * do ativo e imediatamente antes de cada avaliação.
 */
export type ScopeAuthorization = {
  status: "pending" | "approved" | "revoked";
  hostnames: string[];
  excludedHostnames: string[];
  validFrom: Date | null;
  validUntil: Date | null;
};

export type ScopeDecision = { ok: true } | { ok: false; reason: "not_approved" | "revoked" | "not_started" | "expired" | "host_not_in_scope" | "host_excluded" };

export const SCOPE_MESSAGES: Record<Exclude<ScopeDecision, { ok: true }>["reason"], string> = {
  not_approved: "A autorização de escopo ainda não foi aprovada.",
  revoked: "A autorização de escopo foi revogada.",
  not_started: "A janela da autorização de escopo ainda não começou.",
  expired: "A autorização de escopo expirou.",
  host_not_in_scope: "O hostname não está entre os autorizados no escopo.",
  host_excluded: "O hostname está listado como exclusão do escopo."
};

const HOST = /^(\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

/** Normaliza e valida um padrão de hostname: "app.cliente.com" ou "*.cliente.com" (subdomínios, não o domínio raiz). */
export function normalizeHostPattern(raw: string): string | null {
  const value = raw.trim().toLowerCase().replace(/\.$/, "");
  return HOST.test(value) && value.length <= 253 ? value : null;
}

export function hostMatches(pattern: string, hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (!pattern.startsWith("*.")) return pattern === host;
  const suffix = pattern.slice(1);
  return host.endsWith(suffix) && host.length > suffix.length;
}

export function evaluateScope(auth: ScopeAuthorization, hostname: string, now = new Date()): ScopeDecision {
  if (auth.status === "revoked") return { ok: false, reason: "revoked" };
  if (auth.status !== "approved") return { ok: false, reason: "not_approved" };
  if (auth.validFrom && now < auth.validFrom) return { ok: false, reason: "not_started" };
  if (!auth.validUntil || now > auth.validUntil) return { ok: false, reason: "expired" };
  if (auth.excludedHostnames.some(p => hostMatches(p, hostname))) return { ok: false, reason: "host_excluded" };
  if (!auth.hostnames.some(p => hostMatches(p, hostname))) return { ok: false, reason: "host_not_in_scope" };
  return { ok: true };
}

/** Situação exibida na interface. */
export function scopeState(auth: ScopeAuthorization, now = new Date()): "pending" | "active" | "scheduled" | "expired" | "revoked" {
  if (auth.status === "revoked") return "revoked";
  if (auth.status === "pending") return "pending";
  if (auth.validFrom && now < auth.validFrom) return "scheduled";
  if (!auth.validUntil || now > auth.validUntil) return "expired";
  return "active";
}

/** Impressão digital de um achado: identifica o mesmo problema entre avaliações do ativo. */
export const findingFingerprint = (f: { category: string; title: string }) => `${f.category.trim().toLowerCase()}|${f.title.trim().toLowerCase()}`;
