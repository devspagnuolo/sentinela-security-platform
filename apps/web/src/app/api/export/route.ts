import { NextResponse } from "next/server";
import { withAuth } from "@/lib/auth/http";
import { toCsv } from "@/lib/csv";
export const runtime = "nodejs";
export const GET = withAuth("export:download", async ({ repo }, request) => {
  const format = new URL(request.url).searchParams.get("format");
  if (format !== "csv" && format !== "json") return NextResponse.json({ error: "Formato aceito: json ou csv." }, { status: 400 });
  const [assets, findings, assessments] = await Promise.all([repo.listAssets(), repo.listFindings(), repo.listAssessments()]);
  await repo.audit("export.downloaded", "organization", repo.organizationId, { format, findings: findings.length });
  if (format === "csv") {
    const rows = [["id","assetId","title","severity","category","description","evidence","recommendation","discoveredAt"],...findings.map(f => [f.id,f.assetId,f.title,f.severity,f.category,f.description,f.evidence,f.recommendation,f.discoveredAt])];
    return new NextResponse(toCsv(rows), { headers: { "Content-Type":"text/csv; charset=utf-8", "Content-Disposition":"attachment; filename=sentinela-findings.csv" } });
  }
  return NextResponse.json({ generatedAt: new Date().toISOString(), assets, findings, assessments }, { headers: { "Content-Disposition":"attachment; filename=sentinela-assessment.json" } });
});
