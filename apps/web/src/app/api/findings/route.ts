import { NextResponse } from "next/server";
import { requestRepository } from "@/lib/tenant";
export const runtime = "nodejs";
export async function GET() { return NextResponse.json(await (await requestRepository()).listFindings()); }
