import { eq } from "drizzle-orm";
import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { users } from "@/db/schema";
import { withAuth } from "@/lib/auth/http";
import { parseJson, preferencesSchema } from "@/lib/validation";
export const runtime = "nodejs";

/** Preferências da própria conta (hoje: receber os avisos também por e-mail). */
export const PUT = withAuth("asset:read", async ({ user, repo }, request) => {
  const parsed = await parseJson(request, preferencesSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  await (await getDb()).update(users).set({ emailNotifications: parsed.data.emailNotifications }).where(eq(users.id, user.id));
  await repo.audit("user.preferences_updated", "user", user.id, parsed.data);
  return NextResponse.json(parsed.data);
});
