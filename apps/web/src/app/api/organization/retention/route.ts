import { eq } from "drizzle-orm";
import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { retentionView } from "@/db/retention";
import { organizations } from "@/db/schema";
import { withAuth } from "@/lib/auth/http";
import { parseJson, retentionSchema } from "@/lib/validation";
export const runtime = "nodejs";

export const GET = withAuth("org:manage", async ({ organizationId }) => {
  const [org] = await (await getDb()).select().from(organizations).where(eq(organizations.id, organizationId));
  return NextResponse.json(retentionView(org));
});

/** Prazos de retenção (LGPD). Valem a partir da próxima limpeza do worker, em até uma hora. */
export const PUT = withAuth("org:manage", async ({ organizationId, repo }, request) => {
  const parsed = await parseJson(request, retentionSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  const [org] = await (await getDb()).update(organizations).set(parsed.data).where(eq(organizations.id, organizationId)).returning();
  await repo.audit("organization.retention_updated", "organization", organizationId, parsed.data);
  return NextResponse.json(retentionView(org));
});
