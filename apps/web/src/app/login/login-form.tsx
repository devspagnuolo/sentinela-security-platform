"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { LockKeyhole, ShieldCheck } from "lucide-react";

export default function LoginForm() {
  const router = useRouter();
  const [email, setEmail] = useState(""), [password, setPassword] = useState(""), [error, setError] = useState(""), [busy, setBusy] = useState(false);
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setError("");
    try {
      const r = await fetch("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password }) });
      if (r.ok) { router.replace("/"); router.refresh(); return; }
      setError((await r.json()).error ?? "Não foi possível entrar.");
    } catch { setError("Falha de conexão."); }
    setBusy(false);
  }
  return <main className="auth-shell">
    <form className="auth-card" onSubmit={submit}>
      <div className="brand"><div className="brand-mark"><ShieldCheck size={20}/></div><div><b>sentinela</b><span>SECURITY PLATFORM</span></div></div>
      <h1>Entrar</h1>
      <p>Acesso restrito a usuários autorizados da consultoria.</p>
      <label>E-mail<input type="email" autoComplete="username" required value={email} onChange={e => setEmail(e.target.value)} /></label>
      <label>Senha<input type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)} /></label>
      {error && <div className="auth-error" role="alert">{error}</div>}
      <button className="button button-primary" disabled={busy}><LockKeyhole size={15}/>{busy ? "Entrando…" : "Entrar"}</button>
    </form>
  </main>;
}
