import { requireSession } from "@/lib/auth/server";
import AuditLog from "./audit-log";

export const dynamic = "force-dynamic";

export default async function AuditPage() {
  await requireSession("audit:read");
  return <AuditLog />;
}
