import { NextResponse } from "next/server";
import { withAuth } from "@/lib/auth/http";
export const runtime = "nodejs";

export const GET = withAuth("asset:read", async ({ user, role, organizationId, expiresAt }) =>
  NextResponse.json({ user, role, organizationId, expiresAt: expiresAt.toISOString() }, { headers: { "Cache-Control": "no-store" } }));
