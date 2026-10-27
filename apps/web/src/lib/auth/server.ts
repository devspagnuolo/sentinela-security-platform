import "server-only";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { getDb } from "@/db/client";
import { sessionCookieName } from "./http";
import { can, type Permission } from "./rbac";
import { validateSession } from "./session";

/** Sessão da requisição em Server Components; redireciona para /login se ausente e para /conta se faltar o MFA obrigatório. */
export async function requireSession(permission?: Permission, options: { allowDuringMfaEnrollment?: boolean } = {}) {
  const token = (await cookies()).get(sessionCookieName())?.value;
  const session = await validateSession(await getDb(), token);
  if (!session) redirect("/login");
  if (session.mfaEnrollmentRequired && !options.allowDuringMfaEnrollment) redirect("/conta");
  if (permission && !can(session.role, permission)) redirect("/");
  return session;
}

export async function optionalSession() {
  const token = (await cookies()).get(sessionCookieName())?.value;
  return validateSession(await getDb(), token);
}
