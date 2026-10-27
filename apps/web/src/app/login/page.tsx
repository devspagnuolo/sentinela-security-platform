import { redirect } from "next/navigation";
import { optionalSession } from "@/lib/auth/server";
import LoginForm from "./login-form";

export const dynamic = "force-dynamic";

export default async function LoginPage() {
  if (await optionalSession()) redirect("/");
  return <LoginForm />;
}
