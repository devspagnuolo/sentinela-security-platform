import { NextResponse } from "next/server";
import { RepositoryError } from "@/db/repository";
import { withAuth } from "@/lib/auth/http";
export const runtime = "nodejs";

export const POST = withAuth("scope:approve", async ({ repo, user, role }, _request, { params }: { params: Promise<{ id: string }> }) => {
  try {
    return NextResponse.json(await repo.approveAuthorization((await params).id, { id: user.id, role }));
  } catch (error) {
    if (error instanceof RepositoryError) return NextResponse.json({ error: error.message }, { status: error.status });
    throw error;
  }
});
