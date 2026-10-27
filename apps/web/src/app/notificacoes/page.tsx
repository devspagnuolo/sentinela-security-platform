import { requireSession } from "@/lib/auth/server";
import NotificationCenter from "./notification-center";

export const dynamic = "force-dynamic";

export default async function NotificationsPage() {
  await requireSession("asset:read");
  return <NotificationCenter />;
}
