import { NextResponse } from "next/server";
import { RepositoryError } from "@/db/repository";
import { withAuth } from "@/lib/auth/http";
import { parseJson, revokeSchema } from "@/lib/validation";
export const runtime = "nodejs";

/** Revogar bloqueia imediatamente novas avaliações dos ativos vinculados. */
export const POST = withAuth("scope:approve", async ({ repo }, request, { params }: { params: Promise<{ id: string }> }) => {
  const parsed = await parseJson(request, revokeSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  try {
    return NextResponse.json(await repo.revokeAuthorization((await params).id, parsed.data.reason));
  } catch (error) {
    if (error instanceof RepositoryError) return NextResponse.json({ error: error.message }, { status: error.status });
    throw error;
  }
});
