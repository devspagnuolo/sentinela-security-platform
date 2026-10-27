import { NextResponse } from "next/server";
import { store } from "@/lib/store";
export const runtime = "nodejs";

const escapeHtml = (value: unknown) => String(value ?? "").replace(/[&<>"\u0027]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\u0022": "&quot;", "\u0027": "&#39;" } as Record<string, string>)[char] ?? char);
const method = { id: "SENTINELA-HTTP-001", name: "Inspeção não intrusiva de metadados HTTP", request: "Uma requisição HTTPS GET à raiz; sem seguir redirecionamentos; timeout de 5 segundos", checks: ["Headers defensivos", "CORS observado", "Atributos de cookies", "Banners Server e X-Powered-By"], exclusions: ["Exploração", "Teste de autenticação ou autorização", "Varredura de portas", "Crawling", "Análise de corpo ou dados pessoais"] };

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const asset = store.assets.find(item => item.id === id);
  if (!asset) return NextResponse.json({ error: "Ativo não encontrado." }, { status: 404 });
  const run = store.assessments.find(item => item.assetId === id && item.status === "completed");
  if (!run) return NextResponse.json({ error: "Nenhuma avaliação concluída para este ativo." }, { status: 404 });
  const findings = store.findings.filter(item => run.findingIds.includes(item.id));
  const report = {
    version: "0.2", generatedAt: new Date().toISOString(), classification: "Rascunho para revisão do avaliador",
    demonstration: asset.authorizationRef.startsWith("DEMO-"),
    asset: { name: asset.name, url: asset.url, kind: asset.kind, owner: asset.owner },
    authorization: { reference: asset.authorizationRef, approvedInPrototype: asset.approved },
    assessment: { id: run.id, startedAt: run.startedAt, status: run.status, method },
    summary: { total: findings.length, bySeverity: Object.fromEntries(["critical", "high", "medium", "low", "info"].map(severity => [severity, findings.filter(item => item.severity === severity).length])) },
    limitations: "Apenas a raiz HTTPS e metadados da resposta foram observados. Os indicadores exigem revisão contextual; ausência de achados não comprova segurança.",
    findings: findings.map(item => ({ id: item.id, title: item.title, severity: item.severity, category: item.category, observation: item.description, evidence: item.evidence, potentialRisk: "O impacto depende do contexto da aplicação e deve ser validado pelo avaliador.", recommendation: item.recommendation, references: item.references, discoveredAt: item.discoveredAt }))
  };
  const format = new URL(request.url).searchParams.get("format") ?? "json";
  if (format === "json") return NextResponse.json(report, { headers: { "Cache-Control": "no-store", "Content-Disposition": "attachment; filename=sentinela-report-" + id.replace(/[^a-zA-Z0-9-]/g, "") + ".json" } });
  if (format !== "html") return NextResponse.json({ error: "Formato aceito: json ou html." }, { status: 400 });
  const findingHtml = report.findings.map(item => "<article><h3>" + escapeHtml(item.title) + " <small>" + escapeHtml(item.severity) + "</small></h3><p><b>Observação:</b> " + escapeHtml(item.observation) + "</p><p><b>Evidência:</b> " + escapeHtml(item.evidence) + "</p><p><b>Risco potencial:</b> " + escapeHtml(item.potentialRisk) + "</p><p><b>Recomendação:</b> " + escapeHtml(item.recommendation) + "</p><p><b>Referências:</b> " + escapeHtml(item.references.join(", ")) + "</p></article>").join("");
  const html = "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><title>Sentinela - relatório</title><style>body{font:15px Arial,sans-serif;max-width:900px;margin:40px auto;color:#183027;line-height:1.5}h1,h2{color:#176b53}header{border-bottom:3px solid #176b53;margin-bottom:25px}article{border:1px solid #dce9e1;padding:15px;margin:15px 0;break-inside:avoid}small{color:#986d2c}button{padding:9px 14px;background:#176b53;color:white;border:0;border-radius:5px}@media print{body{margin:15mm}button{display:none}}</style></head><body><header><h1>Relatório de avaliação de segurança</h1><p>" + escapeHtml(report.classification) + (report.demonstration ? " · DADOS DEMONSTRATIVOS" : "") + "</p></header><button onclick=\"window.print()\">Salvar ou imprimir PDF</button><h2>Escopo e autorização</h2><p><b>Ativo:</b> " + escapeHtml(report.asset.name) + " (" + escapeHtml(report.asset.url) + ")</p><p><b>Responsável:</b> " + escapeHtml(report.asset.owner) + "</p><p><b>Referência:</b> " + escapeHtml(report.authorization.reference) + "</p><h2>Método utilizado</h2><p>" + escapeHtml(method.name) + " (" + escapeHtml(method.id) + "). " + escapeHtml(method.request) + ".</p><p><b>Verificações:</b> " + escapeHtml(method.checks.join(", ")) + ".</p><p><b>Fora do escopo:</b> " + escapeHtml(method.exclusions.join(", ")) + ".</p><h2>Resumo de riscos</h2><p>" + report.summary.total + " achado(s) registrados. Classificação automática preliminar; revisão humana obrigatória.</p><h2>Achados técnicos</h2>" + (findingHtml || "<p>Nenhum achado nesta avaliação limitada.</p>") + "<h2>Limitações</h2><p>" + escapeHtml(report.limitations) + "</p><p><small>Gerado em " + escapeHtml(report.generatedAt) + " · Execução " + escapeHtml(run.id) + "</small></p></body></html>";
  return new NextResponse(html, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'" } });
}
