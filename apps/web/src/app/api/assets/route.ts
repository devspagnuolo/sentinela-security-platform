import { randomUUID } from "node:crypto";
import { NextResponse } from "next/server";
import { store } from "@/lib/store";
import { validateTarget } from "@/lib/scanner";
import { isHostAllowed } from "@/lib/config";
import { createAssetSchema, firstIssue } from "@/lib/validation";
import type { Asset } from "@/lib/types";
export const runtime = "nodejs";
export async function GET() { return NextResponse.json(store.assets); }
export async function POST(request: Request) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Corpo da requisição deve ser JSON válido." }, { status: 400 }); }
  const parsed = createAssetSchema.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: firstIssue(parsed.error) }, { status: 400 });
  const input = parsed.data;
  try {
    const { url } = await validateTarget(input.url);
    const asset: Asset = { id: randomUUID(), name: input.name || url.hostname, url: url.origin, kind: input.kind, owner: input.owner || "Equipe", approved: isHostAllowed(url.hostname), authorizationRef: input.authorizationRef, createdAt: new Date().toISOString() };
    store.assets.unshift(asset);
    return NextResponse.json(asset, { status: 201 });
  } catch (error) { return NextResponse.json({ error: error instanceof Error ? error.message : "Não foi possível cadastrar o ativo." }, { status: 400 }); }
}
