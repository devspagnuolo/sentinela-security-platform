import type { FindingStatus, ScopeState, Severity } from "./types";

export const FINDING_STATUS_LABELS: Record<FindingStatus, string> = { open: "Aberto", accepted: "Risco aceito", fixed: "Corrigido", false_positive: "Falso positivo" };
export const SEVERITY_LABELS: Record<Severity, string> = { critical: "Crítica", high: "Alta", medium: "Média", low: "Baixa", info: "Informativa" };
export const SCOPE_STATE_LABELS: Record<ScopeState, string> = { pending: "Aguardando aprovação", active: "Vigente", scheduled: "Agendada", expired: "Expirada", revoked: "Revogada" };
