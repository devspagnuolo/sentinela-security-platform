import { NextResponse } from "next/server";
import { getDb } from "@/db/client";
import { notificationRepository } from "@/db/notifications";
import { withAuth } from "@/lib/auth/http";
export const runtime = "nodejs";

/** Avisos do usuário logado na organização atual. */
export const GET = withAuth("asset:read", async ({ organizationId, user }, request) => {
  const inbox = notificationRepository(await getDb(), organizationId, user.id);
  const limit = Number(new URL(request.url).searchParams.get("limit")) || 50;
  const [unread, items] = await Promise.all([inbox.unreadCount(), inbox.list(limit)]);
  return NextResponse.json({ unread, items });
});
