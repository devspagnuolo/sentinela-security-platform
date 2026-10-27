import { NextResponse } from "next/server";
import { withAuth } from "@/lib/auth/http";
import { mailSettings, notificationEmail, smtpTransport } from "@/lib/mail";
export const runtime = "nodejs";

/** Envia agora um e-mail de teste para quem clicou, para conferir a configuração SMTP. */
export const POST = withAuth("integration:manage", async ({ user, repo }) => {
  if (!mailSettings().enabled) return NextResponse.json({ error: "E-mail não configurado. Defina SENTINELA_SMTP_URL e SENTINELA_MAIL_FROM no servidor." }, { status: 409 });
  try {
    await smtpTransport()(notificationEmail({ title: "E-mail de teste", body: "Se você recebeu esta mensagem, os avisos por e-mail do Sentinela estão funcionando.", link: "/notificacoes" }, user));
  } catch (error) {
    const message = error instanceof Error ? error.message : "Falha no envio.";
    await repo.audit("email.tested", "user", user.id, { ok: false, error: message.slice(0, 300) });
    return NextResponse.json({ error: `O servidor SMTP recusou o envio: ${message}` }, { status: 502 });
  }
  await repo.audit("email.tested", "user", user.id, { ok: true });
  return NextResponse.json({ ok: true, to: user.email });
});
