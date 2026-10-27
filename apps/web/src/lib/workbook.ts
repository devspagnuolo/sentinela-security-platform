import { ASSESSMENT_STATUS_LABELS, FINDING_STATUS_LABELS, SCHEDULE_LABELS, SCOPE_STATE_LABELS, SEVERITY_LABELS } from "./labels";
import { SEVERITY_ORDER } from "./report";
import type { Assessment, Asset, Finding } from "./types";
import { buildXlsx, type Sheet } from "./xlsx";

const when = (iso: string | null) => iso ? new Date(iso).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" }) : "";

/** Planilha da organização: achados (com triagem), ativos e avaliações, com rótulos em português. */
export function exportWorkbook(data: { assets: Asset[]; findings: Finding[]; assessments: Assessment[] }) {
  const assetName = new Map(data.assets.map(a => [a.id, a.name]));
  const findings = [...data.findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const sheets: Sheet[] = [
    {
      name: "Achados",
      columns: [{ header: "Ativo", width: 24 }, { header: "Achado", width: 40 }, { header: "Severidade", width: 12 }, { header: "Situação", width: 14 }, { header: "Justificativa da triagem", width: 36 }, { header: "Aceite válido até", width: 18 }, { header: "Categoria", width: 18 }, { header: "Observação", width: 50 }, { header: "Evidência", width: 50 }, { header: "Recomendação", width: 50 }, { header: "Referências", width: 30 }, { header: "Encontrado em", width: 18 }, { header: "Visto por último", width: 18 }, { header: "ID", width: 38 }],
      rows: findings.map(f => [assetName.get(f.assetId) ?? f.assetId, f.title, SEVERITY_LABELS[f.severity], FINDING_STATUS_LABELS[f.status], f.statusReason, when(f.acceptedUntil), f.category, f.description, f.evidence, f.recommendation, f.references.join(", "), when(f.discoveredAt), when(f.lastSeenAt), f.id])
    },
    {
      name: "Ativos",
      columns: [{ header: "Ativo", width: 24 }, { header: "URL", width: 34 }, { header: "Tipo", width: 16 }, { header: "Responsável", width: 20 }, { header: "Autorização", width: 18 }, { header: "Situação do escopo", width: 20 }, { header: "Escopo válido até", width: 18 }, { header: "Reavaliação", width: 12 }, { header: "Próxima reavaliação", width: 18 }, { header: "Achados abertos", width: 14 }, { header: "ID", width: 38 }],
      rows: data.assets.map(a => [a.name, a.url, a.kind, a.owner, a.authorizationRef, a.scopeState ? SCOPE_STATE_LABELS[a.scopeState] : "Sem escopo", when(a.scopeValidUntil), SCHEDULE_LABELS[a.scheduleIntervalDays ?? 0], when(a.nextAssessmentAt), data.findings.filter(f => f.assetId === a.id && f.status === "open").length, a.id])
    },
    {
      name: "Avaliações",
      columns: [{ header: "Ativo", width: 24 }, { header: "Situação", width: 14 }, { header: "Origem", width: 18 }, { header: "Método", width: 20 }, { header: "Pedida em", width: 18 }, { header: "Concluída em", width: 18 }, { header: "Observados", width: 11 }, { header: "Novos", width: 9 }, { header: "Reabertos", width: 10 }, { header: "Corrigidos", width: 10 }, { header: "Erro", width: 40 }, { header: "ID", width: 38 }],
      rows: data.assessments.map(r => [r.assetName ?? assetName.get(r.assetId) ?? r.assetId, ASSESSMENT_STATUS_LABELS[r.status], r.trigger === "scheduled" ? "Agendada" : r.requestedBy?.name ?? "", r.method, when(r.createdAt), when(r.finishedAt), r.summary?.observed, r.summary?.created, r.summary?.reopened, r.summary?.resolved, r.error, r.id])
    }
  ];
  return buildXlsx(sheets);
}
