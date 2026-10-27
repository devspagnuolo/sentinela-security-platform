import { requireSession } from "@/lib/auth/server";
import { canManageRole, ROLES } from "@/lib/auth/rbac";
import UsersManager from "./users-manager";

export const dynamic = "force-dynamic";

export default async function UsersPage() {
  const session = await requireSession("user:read");
  return <UsersManager currentUserId={session.user.id} assignableRoles={ROLES.filter(r => canManageRole(session.role, r))} />;
}
