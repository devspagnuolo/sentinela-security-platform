import { FINDING_STATUS_LABELS, SEVERITY_LABELS, technologyCategoryLabel } from "./labels";
import { SCANNER_METHODS, type ScannerMethod } from "./scanner";
import type { Assessment, Asset, AssetTechnology, Finding, Severity } from "./types";

/** Conteúdo do relatório de um ativo (última execução concluída). JSON, HTML e PDF saem deste mesmo objeto. */
export type Report = ReturnType<typeof buildReport>;
export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function buildReport(asset: Asset, run: Assessment, findings: Finding[], now = new Date(), technologies: AssetTechnology[] = []) {
  const method: ScannerMethod = SCANNER_METHODS[run.method] ?? { id: run.method, name: "Método registrado na execução", request: "Ver metodologia", checks: [], exclusions: [] };
  const sorted = [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  return {
    version: "0.3", generatedAt: now.toISOString(), classification: "Rascunho para revisão do avaliador",
    demonstration: asset.authorizationRef.startsWith("DEMO-"),
    asset: { name: asset.name, url: asset.url, kind: asset.kind, owner: asset.owner },
    authorization: { reference: asset.authorizationRef, state: asset.scopeState, validUntil: asset.scopeValidUntil },
    assessment: { id: run.id, startedAt: run.startedAt, finishedAt: run.finishedAt, status: run.status, method },
    summary: { total: sorted.length, bySeverity: Object.fromEntries(SEVERITY_ORDER.map(severity => [severity, sorted.filter(item => item.severity === severity).length])) },
    limitations: "Apenas a raiz HTTPS, o certificado apresentado nessa conexão e registros DNS públicos foram observados. Os indicadores exigem revisão contextual; ausência de achados não comprova segurança.",
    // Inventário passivo: o que o alvo anuncia (cabeçalhos, certificado, DNS), não necessariamente o que roda por trás.
    technologies: technologies.map(t => ({ category: technologyCategoryLabel(t.category), name: t.name, version: t.version, evidence: t.evidence })),
    findings: sorted.map(item => ({ id: item.id, title: item.title, severity: item.severity, status: item.status, statusReason: item.statusReason, category: item.category, observation: item.description, evidence: item.evidence, potentialRisk: "O impacto depende do contexto da aplicação e deve ser validado pelo avaliador.", recommendation: item.recommendation, references: item.references, discoveredAt: item.discoveredAt }))
  };
}

export const escapeHtml = (value: unknown) => String(value ?? "").replace(/[&<>"\u0027]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\u0022": "&quot;", "\u0027": "&#39;" } as Record<string, string>)[char] ?? char);

/** Versão HTML imprimível. */
export function renderHtml(report: Report) {
  const { method } = report.assessment;
  const findingHtml = report.findings.map(item => "<article><h3>" + escapeHtml(item.title) + " <small>" + escapeHtml(SEVERITY_LABELS[item.severity]) + (item.status !== "open" ? " · " + escapeHtml(FINDING_STATUS_LABELS[item.status]) : "") + "</small></h3>" + (item.statusReason && item.status !== "open" ? "<p><b>Triagem:</b> " + escapeHtml(item.statusReason) + "</p>" : "") + "<p><b>Observação:</b> " + escapeHtml(item.observation) + "</p><p><b>Evidência:</b> " + escapeHtml(item.evidence) + "</p><p><b>Risco potencial:</b> " + escapeHtml(item.potentialRisk) + "</p><p><b>Recomendação:</b> " + escapeHtml(item.recommendation) + "</p><p><b>Referências:</b> " + escapeHtml(item.references.join(", ")) + "</p></article>").join("");
  return "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><title>Sentinela - relatório</title><style>body{font:15px Arial,sans-serif;max-width:900px;margin:40px auto;color:#183027;line-height:1.5}h1,h2{color:#176b53}header{border-bottom:3px solid #176b53;margin-bottom:25px}article{border:1px solid #dce9e1;padding:15px;margin:15px 0;break-inside:avoid}small{color:#986d2c}button{padding:9px 14px;background:#176b53;color:white;border:0;border-radius:5px}@media print{body{margin:15mm}button{display:none}}</style></head><body><header><h1>Relatório de avaliação de segurança</h1><p>" + escapeHtml(report.classification) + (report.demonstration ? " · DADOS DEMONSTRATIVOS" : "") + "</p></header><button onclick=\"window.print()\">Salvar ou imprimir PDF</button><h2>Escopo e autorização</h2><p><b>Ativo:</b> " + escapeHtml(report.asset.name) + " (" + escapeHtml(report.asset.url) + ")</p><p><b>Responsável:</b> " + escapeHtml(report.asset.owner) + "</p><p><b>Referência:</b> " + escapeHtml(report.authorization.reference) + "</p><h2>Método utilizado</h2><p>" + escapeHtml(method.name) + " (" + escapeHtml(method.id) + "). " + escapeHtml(method.request) + ".</p><p><b>Verificações:</b> " + escapeHtml(method.checks.join(", ")) + ".</p><p><b>Fora do escopo:</b> " + escapeHtml(method.exclusions.join(", ")) + ".</p><h2>Resumo de riscos</h2><p>" + report.summary.total + " achado(s) registrados. Classificação automática preliminar; revisão humana obrigatória.</p>" + (report.technologies.length ? "<h2>Tecnologias identificadas</h2><p><small>Indicativo: é o que o alvo anuncia, não necessariamente o que roda por trás.</small></p><ul>" + report.technologies.map(t => "<li><b>" + escapeHtml(t.name) + (t.version ? " " + escapeHtml(t.version) : "") + "</b> · " + escapeHtml(t.category) + " <small>(" + escapeHtml(t.evidence) + ")</small></li>").join("") + "</ul>" : "") + "<h2>Achados técnicos</h2>" + (findingHtml || "<p>Nenhum achado nesta avaliação limitada.</p>") + "<h2>Limitações</h2><p>" + escapeHtml(report.limitations) + "</p><p><small>Gerado em " + escapeHtml(report.generatedAt) + " · Execução " + escapeHtml(report.assessment.id) + "</small></p></body></html>";
}
