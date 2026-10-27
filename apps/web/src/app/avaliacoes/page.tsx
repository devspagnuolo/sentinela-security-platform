import { requireSession } from "@/lib/auth/server";
import AssessmentHistory from "./assessment-history";

export const dynamic = "force-dynamic";

export default async function AssessmentsPage() {
  await requireSession("asset:read");
  return <AssessmentHistory />;
}
