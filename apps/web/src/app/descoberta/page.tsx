import { can } from "@/lib/auth/rbac";
import { requireSession } from "@/lib/auth/server";
import DiscoveryManager from "./discovery-manager";

export const dynamic = "force-dynamic";

export default async function DiscoveryPage() {
  const session = await requireSession("asset:read");
  return <DiscoveryManager canAddAsset={can(session.role, "asset:write")} canManageConnectors={can(session.role, "integration:manage")} />;
}
