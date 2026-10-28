import { requireSession } from "@/lib/auth/server";
import InventoryManager from "./inventory-manager";

export const dynamic = "force-dynamic";

export default async function InventoryPage() {
  await requireSession("asset:read");
  return <InventoryManager />;
}
