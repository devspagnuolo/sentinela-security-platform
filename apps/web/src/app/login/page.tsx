import { redirect } from "next/navigation";
import { optionalSession } from "@/lib/auth/server";
import LoginForm from "./login-form";

export const dynamic = "force-dynamic";

const SSO_ERRORS: Record<string, string> = {
  sso_unavailable: "Não há login SSO configurado para este e-mail. Entre com a senha ou fale com o administrador.",
  sso_expired: "O login SSO expirou ou foi iniciado em outro navegador. Tente novamente.",
  sso_failed: "O provedor de identidade não concluiu o login. Tente novamente.",
  sso_not_provisioned: "Sua conta do provedor não tem acesso a esta plataforma. Peça ao administrador para liberar seu usuário."
};

export default async function LoginPage({ searchParams }: { searchParams: Promise<{ erro?: string }> }) {
  if (await optionalSession()) redirect("/");
  const { erro } = await searchParams;
  return <LoginForm initialError={erro ? SSO_ERRORS[erro] ?? "" : ""} />;
}
