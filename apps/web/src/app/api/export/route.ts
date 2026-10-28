import { NextResponse } from "next/server";
import { withAuth } from "@/lib/auth/http";
import { toCsv } from "@/lib/csv";
import { exportWorkbook } from "@/lib/workbook";
export const runtime = "nodejs";

const XLSX_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

export const GET = withAuth("export:download", async ({ repo }, request) => {
  const format = new URL(request.url).searchParams.get("format");
  if (format !== "csv" && format !== "json" && format !== "xlsx") return NextResponse.json({ error: "Formato aceito: json, csv ou xlsx." }, { status: 400 });
  const [assets, findings, assessments, technologies] = await Promise.all([repo.listAssets(), repo.listFindings(), repo.listAssessments({ limit: 500 }), repo.listTechnologies()]);
  await repo.audit("export.downloaded", "organization", repo.organizationId, { format, findings: findings.length });
  const stamp = new Date().toISOString().slice(0, 10);
  if (format === "xlsx") return new NextResponse(new Uint8Array(exportWorkbook({ assets, findings, assessments, technologies })), { headers: { "Content-Type": XLSX_TYPE, "Cache-Control": "no-store", "Content-Disposition": `attachment; filename=sentinela-${stamp}.xlsx` } });
  if (format === "csv") {
    const rows = [["id","assetId","title","severity","status","statusReason","acceptedUntil","category","description","evidence","recommendation","discoveredAt","lastSeenAt"],...findings.map(f => [f.id,f.assetId,f.title,f.severity,f.status,f.statusReason ?? "",f.acceptedUntil ?? "",f.category,f.description,f.evidence,f.recommendation,f.discoveredAt,f.lastSeenAt])];
    return new NextResponse(toCsv(rows), { headers: { "Content-Type":"text/csv; charset=utf-8", "Content-Disposition":"attachment; filename=sentinela-findings.csv" } });
  }
  return NextResponse.json({ generatedAt: new Date().toISOString(), assets, findings, assessments, technologies }, { headers: { "Content-Disposition":"attachment; filename=sentinela-assessment.json" } });
}, { apiToken: true });
