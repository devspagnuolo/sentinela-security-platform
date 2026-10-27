"use client";
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import ApiTokens from "./api-tokens";
import SsoSettings from "./sso-settings";
import { PersonalDataCard, RetentionSettingsCard } from "./privacy-settings";
import type { RetentionSettings } from "@/lib/retention-options";
import type { Role } from "@/lib/auth/rbac";
import { ArrowLeft, Download, KeyRound, LogOut, Mail, ShieldCheck, ShieldOff } from "lucide-react";

type Props = {
  user: { id: string; email: string; name: string };
  mfaEnabled: boolean; mfaEnrollmentRequired: boolean; recoveryCodesLeft: number;
  canManageOrg: boolean; orgRequiresMfa: boolean; hasPassword: boolean; signedInWithSso: boolean;
  /** Papéis que esta pessoa pode dar a um token de API. */
  tokenRoles: Role[];
  emailNotifications: boolean; mailConfigured: boolean;
  retention: RetentionSettings;
};
type Setup = { secret: string; uri: string; qrSvg: string };

async function post(url: string, body: unknown = {}, method = "POST") {
  const r = await fetch(url, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await r.json().catch(() => ({}));
  return { ok: r.ok, data };
}

function downloadCodes(codes: string[], email: string) {
  const text = `Sentinela: códigos de recuperação de ${email}\nCada código funciona uma única vez.\n\n${codes.join("\n")}\n`;
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  link.download = "sentinela-codigos-de-recuperacao.txt";
  link.click();
  URL.revokeObjectURL(link.href);
}

export default function AccountSettings(props: Props) {
  const router = useRouter();
  const [notice, setNotice] = useState(""), [busy, setBusy] = useState(false);
  const [setup, setSetup] = useState<Setup | null>(null), [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [confirming, setConfirming] = useState<"disable" | "regenerate" | null>(null), [confirmPassword, setConfirmPassword] = useState("");
  const [passwords, setPasswords] = useState({ currentPassword: "", newPassword: "", repeat: "" });

  async function run(action: () => Promise<void>) {
    setBusy(true); setNotice("");
    try { await action(); } catch { setNotice("Falha de conexão."); }
    setBusy(false);
  }
  const startSetup = () => run(async () => {
    const r = await post("/api/auth/mfa/setup");
    if (r.ok) setSetup(r.data); else setNotice(r.data.error ?? "Não foi possível iniciar a configuração.");
  });
  const enable = (e: React.FormEvent) => { e.preventDefault(); void run(async () => {
    const r = await post("/api/auth/mfa/enable", { code });
    if (!r.ok) { setNotice(r.data.error ?? "Código inválido."); return; }
    setSetup(null); setCode(""); setCodes(r.data.recoveryCodes);
    setNotice("Verificação em duas etapas ativada. Guarde os códigos de recuperação abaixo.");
    router.refresh();
  }); };
  const confirm = (e: React.FormEvent) => { e.preventDefault(); void run(async () => {
    const r = await post(confirming === "disable" ? "/api/auth/mfa/disable" : "/api/auth/mfa/recovery-codes", { password: confirmPassword });
    if (!r.ok) { setNotice(r.data.error ?? "Falha na operação."); return; }
    setConfirmPassword("");
    if (confirming === "disable") { setNotice("Verificação em duas etapas desativada."); setCodes(null); }
    else { setCodes(r.data.recoveryCodes); setNotice("Novos códigos gerados. Os anteriores deixaram de funcionar."); }
    setConfirming(null); router.refresh();
  }); };
  const changePassword = (e: React.FormEvent) => { e.preventDefault();
    if (passwords.newPassword !== passwords.repeat) { setNotice("A confirmação não confere com a nova senha."); return; }
    void run(async () => {
      const r = await post("/api/auth/password", { currentPassword: passwords.currentPassword, newPassword: passwords.newPassword });
      setNotice(r.ok ? "Senha alterada. As outras sessões foram encerradas." : r.data.error ?? "Não foi possível alterar a senha.");
      if (r.ok) setPasswords({ currentPassword: "", newPassword: "", repeat: "" });
    });
  };
  const toggleEmail = () => run(async () => {
    const r = await post("/api/auth/preferences", { emailNotifications: !props.emailNotifications }, "PUT");
    setNotice(r.ok ? (props.emailNotifications ? "Você não receberá mais os avisos por e-mail." : "Os avisos também chegarão por e-mail.") : r.data.error ?? "Falha na operação.");
    if (r.ok) router.refresh();
  });
  const toggleOrgMfa = () => run(async () => {
    const r = await post("/api/organization", { requireMfa: !props.orgRequiresMfa }, "PATCH");
    setNotice(r.ok ? (props.orgRequiresMfa ? "A organização não exige mais verificação em duas etapas." : "Verificação em duas etapas agora é obrigatória para todos os usuários.") : r.data.error ?? "Falha na operação.");
    if (r.ok) router.refresh();
  });
  async function logout() { await fetch("/api/auth/logout", { method: "POST" }); router.replace("/login"); router.refresh(); }

  return <main className="content account-page">
    {props.mfaEnrollmentRequired
      ? <button className="button button-secondary" onClick={() => void logout()}><LogOut size={15}/>Sair</button>
      : <Link className="button button-secondary" href="/"><ArrowLeft size={15}/>Voltar ao painel</Link>}
    <h1>Minha conta</h1>
    <p className="muted">{props.user.name} · {props.user.email}</p>
    {props.mfaEnrollmentRequired && <div className="auth-error" role="alert">Sua organização exige verificação em duas etapas. Configure-a para continuar usando a plataforma.</div>}
    {notice && <div className="notice" role="status"><span>{notice}</span></div>}

    <section className="account-card">
      <h2><ShieldCheck size={18}/>Verificação em duas etapas</h2>
      {props.signedInWithSso && <p className="hint">Você entrou pelo SSO da organização; a verificação do provedor já vale para este acesso. O código do app é usado quando você entra com senha.</p>}
      {codes ? <>
        <p>Guarde estes códigos em um local seguro, como um gerenciador de senhas. Cada um permite entrar uma única vez se você perder o celular. Eles não serão exibidos novamente.</p>
        <ul className="recovery-codes">{codes.map(c => <li key={c}><code>{c}</code></li>)}</ul>
        <div className="row-actions">
          <button className="button button-secondary" onClick={() => downloadCodes(codes, props.user.email)}><Download size={15}/>Baixar .txt</button>
          <button className="button button-primary" onClick={() => setCodes(null)}>Já guardei os códigos</button>
        </div>
      </> : props.mfaEnabled ? <>
        <p>Ativa. Restam {props.recoveryCodesLeft} códigos de recuperação.</p>
        {confirming ? <form className="inline-form" onSubmit={confirm}>
          <input type="password" autoComplete="current-password" placeholder="Confirme sua senha" required autoFocus value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} />
          <button className="button button-primary" disabled={busy}>{confirming === "disable" ? "Desativar" : "Gerar novos códigos"}</button>
          <button type="button" className="button button-secondary" onClick={() => { setConfirming(null); setConfirmPassword(""); }}>Cancelar</button>
        </form> : <div className="row-actions">
          <button className="button button-secondary" onClick={() => setConfirming("regenerate")}><KeyRound size={15}/>Gerar novos códigos de recuperação</button>
          <button className="button button-secondary" onClick={() => setConfirming("disable")}><ShieldOff size={15}/>Desativar</button>
        </div>}
      </> : setup ? <form className="mfa-setup" onSubmit={enable}>
        <p>1. Escaneie o QR code com um aplicativo autenticador (Google Authenticator, Microsoft Authenticator, 1Password, Authy…).</p>
        {/* eslint-disable-next-line @next/next/no-img-element -- SVG gerado no servidor, sem otimização de imagem */}
        <img className="qr" alt="QR code para o aplicativo autenticador" src={`data:image/svg+xml;utf8,${encodeURIComponent(setup.qrSvg)}`} width={200} height={200} />
        <p>Sem câmera? Digite a chave manualmente: <code className="secret">{setup.secret.match(/.{1,4}/g)?.join(" ")}</code></p>
        <label>2. Digite o código de 6 dígitos exibido no aplicativo
          <input inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]{6,7}" required autoFocus value={code} onChange={e => setCode(e.target.value)} />
        </label>
        <div className="row-actions">
          <button className="button button-primary" disabled={busy}>Ativar</button>
          <button type="button" className="button button-secondary" onClick={() => setSetup(null)}>Cancelar</button>
        </div>
      </form> : <>
        <p>Proteja sua conta exigindo, além da senha, um código do seu celular a cada login.</p>
        <button className="button button-primary" disabled={busy} onClick={() => void startSetup()}><ShieldCheck size={15}/>Configurar</button>
      </>}
    </section>

    {!props.mfaEnrollmentRequired && <section className="account-card">
      <h2><Mail size={18}/>Avisos por e-mail</h2>
      <p>{props.emailNotifications ? `Os avisos do sino (achados urgentes, avaliações com falha, escopos e aceites de risco) também chegam em ${props.user.email}.` : "Os avisos ficam só no sino da aplicação."}</p>
      {!props.mailConfigured && <p className="hint">O servidor ainda não tem envio de e-mail configurado; até lá, os avisos ficam só no sino.</p>}
      <button className="button button-secondary" disabled={busy} onClick={() => void toggleEmail()}>{props.emailNotifications ? "Desativar e-mails" : "Receber por e-mail"}</button>
    </section>}

    {!props.mfaEnrollmentRequired && <ApiTokens roles={props.tokenRoles} />}

    {props.canManageOrg && <SsoSettings />}

    {props.canManageOrg && <section className="account-card">
      <h2>Política da organização</h2>
      <p>{props.orgRequiresMfa ? "Todos os usuários precisam usar verificação em duas etapas." : "A verificação em duas etapas é opcional para os usuários."}</p>
      <button className="button button-secondary" disabled={busy} onClick={() => void toggleOrgMfa()}>{props.orgRequiresMfa ? "Tornar opcional" : "Exigir de todos os usuários"}</button>
    </section>}

    {props.canManageOrg && <RetentionSettingsCard initial={props.retention} />}

    {!props.mfaEnrollmentRequired && <PersonalDataCard />}

    {props.hasPassword && <section className="account-card">
      <h2><KeyRound size={18}/>Alterar senha</h2>
      <form className="stack-form" onSubmit={changePassword}>
        <input type="password" autoComplete="current-password" placeholder="Senha atual" required value={passwords.currentPassword} onChange={e => setPasswords({ ...passwords, currentPassword: e.target.value })} />
        <input type="password" autoComplete="new-password" placeholder="Nova senha (12+ caracteres)" required minLength={12} value={passwords.newPassword} onChange={e => setPasswords({ ...passwords, newPassword: e.target.value })} />
        <input type="password" autoComplete="new-password" placeholder="Repita a nova senha" required minLength={12} value={passwords.repeat} onChange={e => setPasswords({ ...passwords, repeat: e.target.value })} />
        <button className="button button-primary" disabled={busy}>Alterar senha</button>
      </form>
    </section>}
  </main>;
}
