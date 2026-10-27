import { NextResponse } from "next/server";
import { store } from "@/lib/store";
export async function GET(request: Request) {
  const format = new URL(request.url).searchParams.get("format");
  if (format === "csv") {
    const quote = (v: unknown) => `"${String(v ?? "").replaceAll('"','""')}"`;
    const rows = [["id","assetId","title","severity","category","description","evidence","recommendation","discoveredAt"],...store.findings.map(f => [f.id,f.assetId,f.title,f.severity,f.category,f.description,f.evidence,f.recommendation,f.discoveredAt])];
    return new NextResponse(rows.map(row => row.map(quote).join(",")).join("\r\n"), { headers: { "Content-Type":"text/csv; charset=utf-8", "Content-Disposition":"attachment; filename=sentinela-findings.csv" } });
  }
  if (format === "json") return NextResponse.json({ generatedAt: new Date().toISOString(), assets: store.assets, findings: store.findings, assessments: store.assessments }, { headers: { "Content-Disposition":"attachment; filename=sentinela-assessment.json" } });
  return NextResponse.json({ error: "Formato aceito: json ou csv." }, { status: 400 });
}
