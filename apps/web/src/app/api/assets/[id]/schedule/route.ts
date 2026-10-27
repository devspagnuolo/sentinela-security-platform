import { NextResponse } from "next/server";
import { RepositoryError } from "@/db/repository";
import { withAuth } from "@/lib/auth/http";
import { parseJson, scheduleSchema } from "@/lib/validation";
export const runtime = "nodejs";

export const PUT = withAuth("asset:write", async ({ repo }, request, { params }: { params: Promise<{ id: string }> }) => {
  const parsed = await parseJson(request, scheduleSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  try {
    return NextResponse.json(await repo.setSchedule((await params).id, parsed.data.intervalDays || null));
  } catch (error) {
    if (error instanceof RepositoryError) return NextResponse.json({ error: error.message }, { status: error.status });
    throw error;
  }
});
