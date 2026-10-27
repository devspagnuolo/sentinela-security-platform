import { NextResponse } from "next/server";
import { RepositoryError } from "@/db/repository";
import { forbidden, withAuth } from "@/lib/auth/http";
import { can } from "@/lib/auth/rbac";
import { findingStatusSchema, parseJson } from "@/lib/validation";
export const runtime = "nodejs";

/** Triagem: Analista marca falso positivo, corrigido ou reabre; aceitar risco exige Admin ou Owner. */
export const PATCH = withAuth("finding:triage", async ({ repo, role }, request, { params }: { params: Promise<{ id: string }> }) => {
  const parsed = await parseJson(request, findingStatusSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  if (parsed.data.status === "accepted" && !can(role, "finding:accept")) return forbidden();
  try {
    return NextResponse.json(await repo.updateFindingStatus((await params).id, parsed.data));
  } catch (error) {
    if (error instanceof RepositoryError) return NextResponse.json({ error: error.message }, { status: error.status });
    throw error;
  }
}, { apiToken: true });
