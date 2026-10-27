import { randomUUID } from "node:crypto";
import { NextResponse } from "next/server";
import { store } from "@/lib/store";
import { validateTarget } from "@/lib/scanner";
export const runtime = "nodejs";
export async function GET() { return NextResponse.json(store.assets); }
export async function POST(request: Request) {
  try {
    const body = await request.json();
    if (body?.authorized !== true || typeof body.authorizationRef !== "string" || body.authorizationRef.trim().length < 4) return NextResponse.json({ error: "Confirme a autorização formal e informe a referência do documento." }, { status: 400 });
    const url = await validateTarget(String(body.url ?? ""));
    const asset = { id: randomUUID(), name: String(body.name ?? url.hostname).slice(0,100), url: url.origin, kind: body.kind === "API" ? "API" as const : "Web application" as const, owner: String(body.owner ?? "Equipe").slice(0,100), approved: false, authorizationRef: body.authorizationRef.trim().slice(0,120), createdAt: new Date().toISOString() };
    store.assets.unshift(asset);
    return NextResponse.json(asset, { status: 201 });
  } catch (error) { return NextResponse.json({ error: error instanceof Error ? error.message : "Não foi possível cadastrar o ativo." }, { status: 400 }); }
}
