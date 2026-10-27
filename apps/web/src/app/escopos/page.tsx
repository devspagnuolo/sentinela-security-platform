import { can } from "@/lib/auth/rbac";
import { requireSession } from "@/lib/auth/server";
import ScopesManager from "./scopes-manager";

export const dynamic = "force-dynamic";

export default async function ScopesPage() {
  const session = await requireSession("asset:read");
  return <ScopesManager currentUserId={session.user.id} isOwner={session.role === "owner"} canWrite={can(session.role, "scope:write")} canApprove={can(session.role, "scope:approve")} />;
}
