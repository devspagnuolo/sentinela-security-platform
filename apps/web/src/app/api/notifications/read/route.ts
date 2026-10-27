import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { notificationRepository } from "@/db/notifications";
import { withAuth } from "@/lib/auth/http";
import { markReadSchema, parseJson } from "@/lib/validation";
export const runtime = "nodejs";

/** Marca avisos como lidos: os ids informados, ou todos sem ids. */
export const POST = withAuth("asset:read", async ({ organizationId, user }, request) => {
  const parsed = await parseJson(request, markReadSchema);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 });
  const inbox = notificationRepository(await getDb(), organizationId, user.id);
  const marked = await inbox.markRead(parsed.data.ids);
  return NextResponse.json({ marked, unread: await inbox.unreadCount() });
});
