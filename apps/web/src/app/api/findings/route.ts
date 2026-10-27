import { NextResponse } from "next/server";
import { withAuth } from "@/lib/auth/http";
export const runtime = "nodejs";
export const GET = withAuth("asset:read", async ({ repo }) => NextResponse.json(await repo.listFindings()));
