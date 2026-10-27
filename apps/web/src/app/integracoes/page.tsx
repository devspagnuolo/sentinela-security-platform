import { requireSession } from "@/lib/auth/server";
import { can } from "@/lib/auth/rbac";
import IntegrationsManager from "./integrations-manager";

export const dynamic = "force-dynamic";

export default async function IntegrationsPage() {
  const session = await requireSession("integration:manage");
  return <IntegrationsManager canManageTokens={can(session.role, "user:manage")} />;
}
