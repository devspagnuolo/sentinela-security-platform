export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "open" | "accepted" | "fixed" | "false_positive";
export type ScopeState = "pending" | "active" | "scheduled" | "expired" | "revoked";
export type Asset = {
  id: string;
  name: string;
  url: string;
  kind: "Web application" | "API";
  owner: string;
  authorizationRef: string;
  authorizationId: string | null;
  /** Situação da autorização vinculada agora; scopeOk diz se o hostname está liberado para avaliação. */
  scopeState: ScopeState | null;
  scopeOk: boolean;
  scopeMessage: string | null;
  scopeValidUntil: string | null;
  /** Reavaliação periódica (null = só manual) e a próxima execução prevista. */
  scheduleIntervalDays: number | null;
  nextAssessmentAt: string | null;
  lastAssessment: Pick<Assessment, "id" | "status" | "error" | "createdAt" | "finishedAt"> | null;
  createdAt: string;
};
export type Finding = {
  id: string;
  assetId: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  evidence: string;
  recommendation: string;
  references: string[];
  status: FindingStatus;
  statusReason: string | null;
  statusChangedAt: string | null;
  acceptedUntil: string | null;
  discoveredAt: string;
  lastSeenAt: string;
};
export type FindingEvent = { id: string; fromStatus: FindingStatus | null; toStatus: FindingStatus; reason: string | null; actorName: string | null; createdAt: string };
export type Authorization = {
  id: string;
  reference: string;
  clientName: string | null;
  hostnames: string[];
  excludedHostnames: string[];
  validFrom: string | null;
  validUntil: string | null;
  emergencyContact: string | null;
  notes: string | null;
  status: "pending" | "approved" | "revoked";
  state: ScopeState;
  createdBy: { id: string; name: string } | null;
  approvedBy: { id: string; name: string } | null;
  approvedAt: string | null;
  revokedAt: string | null;
  revokeReason: string | null;
  assetCount: number;
  createdAt: string;
};
export type AssessmentStatus = "queued" | "running" | "completed" | "failed";
export type AssessmentSummary = { observed: number; created: number; reopened: number; resolved: number };
export type Assessment = {
  id: string;
  assetId: string;
  assetName?: string;
  status: AssessmentStatus;
  trigger: "manual" | "scheduled";
  /** Versão do método do scanner usada (ex.: SENTINELA-WEB-002). */
  method: string;
  requestedBy: { id: string; name: string } | null;
  attempts: number;
  error: string | null;
  summary: AssessmentSummary | null;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  findingIds: string[];
};
export type Notification = { id: string; kind: string; title: string; body: string; link: string | null; readAt: string | null; createdAt: string };

/** Tecnologia identificada passivamente num ativo (src/lib/fingerprint.ts). */
export type AssetTechnology = {
  id: string; assetId: string; assetName: string; category: string; name: string; version: string | null; evidence: string;
  /** Apareceu na última avaliação concluída do ativo. */
  current: boolean;
  firstSeenAt: string; lastSeenAt: string;
};
