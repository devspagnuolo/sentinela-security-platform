import { NextResponse } from "next/server";
import { withAuth } from "@/lib/auth/http";
export const runtime = "nodejs";

export const GET = withAuth("asset:read", async ({ repo }, _request, { params }: { params: Promise<{ id: string }> }) => {
  const { id } = await params;
  if (!(await repo.getFinding(id))) return NextResponse.json({ error: "Achado não encontrado." }, { status: 404 });
  return NextResponse.json(await repo.listFindingEvents(id), { headers: { "Cache-Control": "no-store" } });
});
