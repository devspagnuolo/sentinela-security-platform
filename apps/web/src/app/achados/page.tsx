import { can } from "@/lib/auth/rbac";
import { requireSession } from "@/lib/auth/server";
import FindingsManager from "./findings-manager";

export const dynamic = "force-dynamic";

export default async function FindingsPage() {
  const session = await requireSession("asset:read");
  return <FindingsManager canTriage={can(session.role, "finding:triage")} canAccept={can(session.role, "finding:accept")} />;
}
