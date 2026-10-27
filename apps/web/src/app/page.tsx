import { requireSession } from "@/lib/auth/server";
import { can, type Permission } from "@/lib/auth/rbac";
import Dashboard from "./dashboard";

export const dynamic = "force-dynamic";

const permissions: Permission[] = ["asset:read", "asset:write", "assessment:run", "report:read", "export:download", "audit:read", "user:read", "user:manage", "integration:manage"];

export default async function Home() {
  const session = await requireSession();
  return <Dashboard viewer={{ name: session.user.name, email: session.user.email, role: session.role, permissions: permissions.filter(p => can(session.role, p)) }} />;
}
