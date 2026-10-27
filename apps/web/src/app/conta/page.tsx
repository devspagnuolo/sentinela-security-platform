import { eq } from "drizzle-orm";
import { getDb } from "@/db/client";
import { organizations, users } from "@/db/schema";
import { remainingRecoveryCodes } from "@/lib/auth/mfa";
import { can } from "@/lib/auth/rbac";
import { requireSession } from "@/lib/auth/server";
import AccountSettings from "./account-settings";

export const dynamic = "force-dynamic";

export default async function AccountPage() {
  const session = await requireSession(undefined, { allowDuringMfaEnrollment: true });
  const db = await getDb();
  const [account] = await db.select({ passwordHash: users.passwordHash }).from(users).where(eq(users.id, session.user.id));
  const [org] = await db.select({ requireMfa: organizations.requireMfa }).from(organizations).where(eq(organizations.id, session.organizationId));
  return <AccountSettings
    user={session.user}
    mfaEnabled={session.mfaEnabled}
    mfaEnrollmentRequired={session.mfaEnrollmentRequired}
    recoveryCodesLeft={session.mfaEnabled ? await remainingRecoveryCodes(db, session.user.id) : 0}
    canManageOrg={can(session.role, "org:manage")}
    orgRequiresMfa={org.requireMfa}
    hasPassword={Boolean(account?.passwordHash)}
    signedInWithSso={session.authMethod === "sso"}
  />;
}
