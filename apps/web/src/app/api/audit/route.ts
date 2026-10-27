import { NextResponse } from "next/server";
import type { AuditEntry } from "@/db/repository";
import { withAuth } from "@/lib/auth/http";
import { isAuditCategory } from "@/lib/audit";
import { toCsv } from "@/lib/csv";
export const runtime = "nodejs";

const CSV_MAX_ROWS = 10_000;

/** GET /api/audit?limit=&before=<seq>&category=auth&format=csv */
export const GET = withAuth("audit:read", async ({ repo }, request) => {
  const params = new URL(request.url).searchParams;
  const category = params.get("category");
  if (category && !isAuditCategory(category)) return NextResponse.json({ error: "Categoria inválida." }, { status: 400 });
  const before = params.has("before") ? Number(params.get("before")) : undefined;
  if (before !== undefined && !Number.isSafeInteger(before)) return NextResponse.json({ error: "Cursor inválido." }, { status: 400 });
  const query = { before, actionPrefix: category ? `${category}.` : undefined };

  if (params.get("format") === "csv") {
    const entries: AuditEntry[] = [];
    let cursor = before;
    while (entries.length < CSV_MAX_ROWS) {
      const page = await repo.listAudit(500, { ...query, before: cursor });
      entries.push(...page);
      if (page.length < 500) break;
      cursor = page.at(-1)!.seq;
    }
    await repo.audit("export.audit_downloaded", "organization", repo.organizationId, { rows: entries.length, category });
    const rows = [["data", "acao", "autor", "email_autor", "alvo_tipo", "alvo_id", "detalhes"], ...entries.map(e => [e.createdAt, e.action, e.actorName, e.actorEmail, e.targetType, e.targetId, e.metadata])];
    return new NextResponse(toCsv(rows), { headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": "attachment; filename=sentinela-auditoria.csv", "Cache-Control": "no-store" } });
  }

  const limit = Number(params.get("limit") ?? 100);
  return NextResponse.json(await repo.listAudit(Number.isFinite(limit) ? limit : 100, query), { headers: { "Cache-Control": "no-store" } });
});
