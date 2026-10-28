import type { AssessmentStatus, FindingStatus, ScopeState, Severity } from "./types";

export const FINDING_STATUS_LABELS: Record<FindingStatus, string> = { open: "Aberto", accepted: "Risco aceito", fixed: "Corrigido", false_positive: "Falso positivo" };
export const SEVERITY_LABELS: Record<Severity, string> = { critical: "Crítica", high: "Alta", medium: "Média", low: "Baixa", info: "Informativa" };
export const SCOPE_STATE_LABELS: Record<ScopeState, string> = { pending: "Aguardando aprovação", active: "Vigente", scheduled: "Agendada", expired: "Expirada", revoked: "Revogada" };
export const ASSESSMENT_STATUS_LABELS: Record<AssessmentStatus, string> = { queued: "Na fila", running: "Executando", completed: "Concluída", failed: "Não concluída" };
export const SCHEDULE_LABELS: Record<number, string> = { 0: "Manual", 1: "Diária", 7: "Semanal", 30: "Mensal" };

/** "há 5 min", "há 2 h", "há 3 dias" (ou "agora"). */
export function timeAgo(iso: string | null, now = Date.now()) {
  if (!iso) return "—";
  const minutes = Math.round((now - new Date(iso).getTime()) / 60_000);
  if (minutes < 1) return "agora";
  if (minutes < 60) return `há ${minutes} min`;
  if (minutes < 48 * 60) return `há ${Math.round(minutes / 60)} h`;
  return `há ${Math.round(minutes / 1440)} dias`;
}

/** Categorias do inventário passivo de tecnologias (src/lib/fingerprint.ts). */
export const TECHNOLOGY_CATEGORY_LABELS = {
  server: "Servidor web",
  framework: "Linguagem e framework",
  platform: "Plataforma e CMS",
  edge: "CDN, WAF e balanceador",
  hosting: "Hospedagem",
  certificate: "Autoridade certificadora",
  email: "E-mail",
  dns: "DNS"
} as const;
export type TechnologyCategory = keyof typeof TECHNOLOGY_CATEGORY_LABELS;
export const technologyCategoryLabel = (category: string) => TECHNOLOGY_CATEGORY_LABELS[category as TechnologyCategory] ?? category;
