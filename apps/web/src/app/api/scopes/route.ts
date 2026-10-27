import { NextResponse } from "next/server";
import { withAuth } from "@/lib/auth/http";
import { authorizationSchema, parseJson } from "@/lib/validation";
export const runtime = "nodejs";

export const GET = withAuth("asset:read", async ({ repo }) => NextResponse.json(await repo.listAuthorizations(), { headers: { "Cache-Control": "no-store" } }));

/** Cadastra uma autorização de escopo; ela nasce pendente e só vale depois de aprovada. */
export const POST = withAuth("scope:write", async ({ repo }, request) => {
  const parsed = await parseJson(request, authorizationSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  return NextResponse.json(await repo.createAuthorization(parsed.data), { status: 201 });
});
