"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { KeyRound, LockKeyhole, ShieldCheck } from "lucide-react";

export default function LoginForm() {
  const router = useRouter();
  const [email, setEmail] = useState(""), [password, setPassword] = useState(""), [error, setError] = useState(""), [busy, setBusy] = useState(false);
  const [challenge, setChallenge] = useState(""), [code, setCode] = useState("");
  async function post(url: string, body: unknown) {
    return fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  }
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setError("");
    try {
      const r = challenge ? await post("/api/auth/mfa/verify", { challenge, code }) : await post("/api/auth/login", { email, password });
      const data = await r.json();
      if (r.ok && data.mfaRequired) { setChallenge(data.challenge); setPassword(""); setBusy(false); return; }
      if (r.ok) { router.replace("/"); router.refresh(); return; }
      setError(data.error ?? "Não foi possível entrar.");
    } catch { setError("Falha de conexão."); }
    setBusy(false);
  }
  function restart() { setChallenge(""); setCode(""); setError(""); }
  return <main className="auth-shell">
    <form className="auth-card" onSubmit={submit}>
      <div className="brand"><div className="brand-mark"><ShieldCheck size={20}/></div><div><b>sentinela</b><span>SECURITY PLATFORM</span></div></div>
      {challenge ? <>
        <h1>Verificação em duas etapas</h1>
        <p>Digite o código de 6 dígitos do seu aplicativo autenticador ou um código de recuperação.</p>
        <label>Código<input autoComplete="one-time-code" inputMode="text" autoFocus required minLength={6} maxLength={20} value={code} onChange={e => setCode(e.target.value)} /></label>
        {error && <div className="auth-error" role="alert">{error}</div>}
        <button className="button button-primary" disabled={busy}><KeyRound size={15}/>{busy ? "Verificando…" : "Verificar"}</button>
        <button type="button" className="link-button" onClick={restart}>Voltar e entrar com outra conta</button>
      </> : <>
        <h1>Entrar</h1>
        <p>Acesso restrito a usuários autorizados da consultoria.</p>
        <label>E-mail<input type="email" autoComplete="username" required value={email} onChange={e => setEmail(e.target.value)} /></label>
        <label>Senha<input type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)} /></label>
        {error && <div className="auth-error" role="alert">{error}</div>}
        <button className="button button-primary" disabled={busy}><LockKeyhole size={15}/>{busy ? "Entrando…" : "Entrar"}</button>
      </>}
    </form>
  </main>;
}
