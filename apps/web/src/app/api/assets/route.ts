import { NextResponse } from "next/server";
import { RepositoryError } from "@/db/repository";
import { validateTarget } from "@/lib/scanner";
import { withAuth } from "@/lib/auth/http";
import { createAssetSchema, parseJson } from "@/lib/validation";
export const runtime = "nodejs";

export const GET = withAuth("asset:read", async ({ repo }) => NextResponse.json(await repo.listAssets()), { apiToken: true });

export const POST = withAuth("asset:write", async ({ repo }, request) => {
  const parsed = await parseJson(request, createAssetSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  const input = parsed.data;
  let url: URL;
  try { ({ url } = await validateTarget(input.url)); } catch (error) { return NextResponse.json({ error: error instanceof Error ? error.message : "Não foi possível cadastrar o ativo." }, { status: 400 }); }
  try {
    const asset = await repo.createAsset({ name: input.name || url.hostname, url: url.origin, kind: input.kind, owner: input.owner || "Equipe", authorizationId: input.authorizationId });
    return NextResponse.json(asset, { status: 201 });
  } catch (error) {
    if (error instanceof RepositoryError) return NextResponse.json({ error: error.message }, { status: error.status });
    throw error;
  }
}, { apiToken: true });
