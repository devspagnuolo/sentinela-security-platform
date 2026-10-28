import { NextResponse } from "next/server";
import { withAuth } from "@/lib/auth/http";
import { renderPdf } from "@/lib/pdf";
import { buildReport, renderHtml } from "@/lib/report";
export const runtime = "nodejs";

const FORMATS = ["json", "html", "pdf"] as const;

export const GET = withAuth("report:read", async ({ repo }, request, { params }: { params: Promise<{ id: string }> }) => {
  const { id } = await params;
  const format = new URL(request.url).searchParams.get("format") ?? "json";
  if (!FORMATS.includes(format as never)) return NextResponse.json({ error: "Formato aceito: json, html ou pdf." }, { status: 400 });
  const asset = await repo.getAsset(id);
  if (!asset) return NextResponse.json({ error: "Ativo não encontrado." }, { status: 404 });
  const latest = await repo.latestCompletedAssessment(id);
  if (!latest) return NextResponse.json({ error: "Nenhuma avaliação concluída para este ativo." }, { status: 404 });
  const report = buildReport(asset, latest.run, latest.findings, new Date(), await repo.listTechnologies({ assetId: id }));
  await repo.audit("report.generated", "asset", asset.id, { assessmentId: latest.run.id, format });
  const filename = `sentinela-report-${asset.name.normalize("NFD").replace(/\p{Diacritic}/gu, "").replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-|-$/g, "").toLowerCase() || "ativo"}-${report.generatedAt.slice(0, 10)}`;
  if (format === "json") return NextResponse.json(report, { headers: { "Cache-Control": "no-store", "Content-Disposition": `attachment; filename=${filename}.json` } });
  if (format === "pdf") return new NextResponse(Buffer.from(await renderPdf(report)), { headers: { "Content-Type": "application/pdf", "Cache-Control": "no-store", "Content-Disposition": `attachment; filename=${filename}.pdf` } });
  return new NextResponse(renderHtml(report), { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'" } });
}, { apiToken: true });
