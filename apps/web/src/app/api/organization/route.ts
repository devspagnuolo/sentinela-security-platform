import { eq } from "drizzle-orm";
import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { organizations } from "@/db/schema";
import { withAuth } from "@/lib/auth/http";
import { organizationSchema, parseJson } from "@/lib/validation";
export const runtime = "nodejs";

const view = (org: typeof organizations.$inferSelect) => ({ id: org.id, name: org.name, slug: org.slug, requireMfa: org.requireMfa });

export const GET = withAuth("asset:read", async ({ organizationId }) => {
  const [org] = await (await getDb()).select().from(organizations).where(eq(organizations.id, organizationId));
  return NextResponse.json(view(org));
});

export const PATCH = withAuth("org:manage", async ({ organizationId, repo, mfaEnabled }, request) => {
  const parsed = await parseJson(request, organizationSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  if (parsed.data.requireMfa && !mfaEnabled) return NextResponse.json({ error: "Ative a sua verificação em duas etapas antes de exigi-la da organização." }, { status: 409 });
  const [org] = await (await getDb()).update(organizations).set(parsed.data).where(eq(organizations.id, organizationId)).returning();
  await repo.audit("organization.updated", "organization", organizationId, parsed.data);
  return NextResponse.json(view(org));
});
