"use client";
import { useEffect, useState } from "react";
import { Building2 } from "lucide-react";

type SsoView = { configured: boolean; redirectUri: string; issuer?: string; clientId?: string; allowedDomains?: string[]; enabled?: boolean; enforced?: boolean; jitRole?: "analyst" | "viewer" | null };
type Form = { issuer: string; clientId: string; clientSecret: string; domains: string; enabled: boolean; enforced: boolean; jitRole: "" | "analyst" | "viewer" };

const toForm = (v: SsoView): Form => ({ issuer: v.issuer ?? "", clientId: v.clientId ?? "", clientSecret: "", domains: v.allowedDomains?.join(", ") ?? "", enabled: v.enabled ?? true, enforced: v.enforced ?? false, jitRole: v.jitRole ?? "" });

export default function SsoSettings() {
  const [view, setView] = useState<SsoView | null>(null), [form, setForm] = useState<Form | null>(null);
  const [notice, setNotice] = useState(""), [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    fetch("/api/organization/sso").then(r => r.ok ? r.json() : null).then((v: SsoView | null) => { if (active && v) { setView(v); setForm(toForm(v)); } });
    return () => { active = false; };
  }, []);
  if (!view || !form) return null;

  const set = (changes: Partial<Form>) => setForm({ ...form, ...changes });
  async function save(e: React.FormEvent) {
    e.preventDefault(); if (!form) return;
    setBusy(true); setNotice("");
    try {
      const r = await fetch("/api/organization/sso", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
        issuer: form.issuer, clientId: form.clientId, ...(form.clientSecret && { clientSecret: form.clientSecret }),
        allowedDomains: form.domains.split(/[\s,;]+/).filter(Boolean), enabled: form.enabled, enforced: form.enabled && form.enforced, jitRole: form.jitRole || null
      }) });
      const data = await r.json();
      if (r.ok) { setView(data); setForm(toForm(data)); setNotice("Configuração de SSO salva e emissor verificado."); }
      else setNotice(data.error ?? "Não foi possível salvar.");
    } catch { setNotice("Falha de conexão."); }
    setBusy(false);
  }

  return <section className="account-card">
    <h2><Building2 size={18}/>Login via SSO (OIDC)</h2>
    <p>Conecte o Google Workspace, Microsoft Entra ID, Okta ou outro provedor OpenID Connect. Registre no provedor um aplicativo web com este endereço de retorno:</p>
    <p className="hint"><code>{view.redirectUri}</code></p>
    {notice && <div className="notice" role="status"><span>{notice}</span></div>}
    <form className="sso-form" onSubmit={save}>
      <label>Issuer (emissor)
        <input type="url" required placeholder="https://accounts.google.com" value={form.issuer} onChange={e => set({ issuer: e.target.value })} />
        <span className="hint">Entra ID: https://login.microsoftonline.com/&lt;tenant-id&gt;/v2.0 · Okta: https://&lt;sua-org&gt;.okta.com</span>
      </label>
      <label>Client ID<input required value={form.clientId} onChange={e => set({ clientId: e.target.value })} /></label>
      <label>Client secret<input type="password" autoComplete="off" required={!view.configured} placeholder={view.configured ? "Deixe em branco para manter o atual" : ""} value={form.clientSecret} onChange={e => set({ clientSecret: e.target.value })} /></label>
      <label>Domínios de e-mail permitidos<input required placeholder="suaempresa.com.br" value={form.domains} onChange={e => set({ domains: e.target.value })} /></label>
      <label>Novos usuários no primeiro acesso
        <select value={form.jitRole} onChange={e => set({ jitRole: e.target.value as Form["jitRole"] })}>
          <option value="">Não criar: só quem já foi cadastrado em Usuários</option>
          <option value="viewer">Criar como Leitor</option>
          <option value="analyst">Criar como Analista</option>
        </select>
      </label>
      <label className="checkbox"><input type="checkbox" checked={form.enabled} onChange={e => set({ enabled: e.target.checked })} />SSO ativo</label>
      <label className="checkbox"><input type="checkbox" checked={form.enforced} disabled={!form.enabled} onChange={e => set({ enforced: e.target.checked })} />Exigir SSO (Owners continuam podendo entrar com senha, para emergências)</label>
      <button className="button button-primary" disabled={busy}>{busy ? "Verificando o emissor…" : "Salvar"}</button>
    </form>
  </section>;
}
