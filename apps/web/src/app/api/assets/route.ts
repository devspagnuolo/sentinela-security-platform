import { NextResponse } from "next/server";
import { validateTarget } from "@/lib/scanner";
import { isHostAllowed } from "@/lib/config";
import { requestRepository } from "@/lib/tenant";
import { createAssetSchema, firstIssue } from "@/lib/validation";
export const runtime = "nodejs";
export async function GET() { return NextResponse.json(await (await requestRepository()).listAssets()); }
export async function POST(request: Request) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Corpo da requisição deve ser JSON válido." }, { status: 400 }); }
  const parsed = createAssetSchema.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: firstIssue(parsed.error) }, { status: 400 });
  const input = parsed.data;
  let url: URL;
  try { ({ url } = await validateTarget(input.url)); } catch (error) { return NextResponse.json({ error: error instanceof Error ? error.message : "Não foi possível cadastrar o ativo." }, { status: 400 }); }
  const repo = await requestRepository();
  const asset = await repo.createAsset({ name: input.name || url.hostname, url: url.origin, kind: input.kind, owner: input.owner || "Equipe", approved: isHostAllowed(url.hostname), authorizationRef: input.authorizationRef });
  return NextResponse.json(asset, { status: 201 });
}
