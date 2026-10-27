import { eq } from "drizzle-orm";
import { getDb } from "@/db/client";
import { retentionView } from "@/db/retention";
import { organizations, users } from "@/db/schema";
import { remainingRecoveryCodes } from "@/lib/auth/mfa";
import { can, rankOf } from "@/lib/auth/rbac";
import { TOKEN_ROLES } from "@/lib/auth/tokens";
import { mailSettings } from "@/lib/mail";
import { requireSession } from "@/lib/auth/server";
import AccountSettings from "./account-settings";

export const dynamic = "force-dynamic";

export default async function AccountPage() {
  const session = await requireSession(undefined, { allowDuringMfaEnrollment: true });
  const db = await getDb();
  const [account] = await db.select({ passwordHash: users.passwordHash, emailNotifications: users.emailNotifications }).from(users).where(eq(users.id, session.user.id));
  const [org] = await db.select().from(organizations).where(eq(organizations.id, session.organizationId));
  return <AccountSettings
    user={session.user}
    mfaEnabled={session.mfaEnabled}
    mfaEnrollmentRequired={session.mfaEnrollmentRequired}
    recoveryCodesLeft={session.mfaEnabled ? await remainingRecoveryCodes(db, session.user.id) : 0}
    canManageOrg={can(session.role, "org:manage")}
    orgRequiresMfa={org.requireMfa}
    retention={retentionView(org)}
    hasPassword={Boolean(account?.passwordHash)}
    signedInWithSso={session.authMethod === "sso"}
    emailNotifications={account?.emailNotifications ?? true}
    mailConfigured={mailSettings().enabled}
    tokenRoles={TOKEN_ROLES.filter(r => rankOf(r) <= rankOf(session.role))}
  />;
}
