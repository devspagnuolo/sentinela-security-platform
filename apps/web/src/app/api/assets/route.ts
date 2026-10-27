import { NextResponse } from "next/server";
import { validateTarget } from "@/lib/scanner";
import { isHostAllowed } from "@/lib/config";
import { withAuth } from "@/lib/auth/http";
import { createAssetSchema, parseJson } from "@/lib/validation";
export const runtime = "nodejs";

export const GET = withAuth("asset:read", async ({ repo }) => NextResponse.json(await repo.listAssets()));

export const POST = withAuth("asset:write", async ({ repo }, request) => {
  const parsed = await parseJson(request, createAssetSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  const input = parsed.data;
  let url: URL;
  try { ({ url } = await validateTarget(input.url)); } catch (error) { return NextResponse.json({ error: error instanceof Error ? error.message : "Não foi possível cadastrar o ativo." }, { status: 400 }); }
  const asset = await repo.createAsset({ name: input.name || url.hostname, url: url.origin, kind: input.kind, owner: input.owner || "Equipe", approved: isHostAllowed(url.hostname), authorizationRef: input.authorizationRef });
  return NextResponse.json(asset, { status: 201 });
});
