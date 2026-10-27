"use client";
import { useCallback, useEffect, useState } from "react";
import { Copy, KeySquare, Plus } from "lucide-react";
import { ROLE_LABELS, type Role } from "@/lib/auth/rbac";
import type { ApiToken } from "@/lib/auth/tokens";

const date = (iso: string) => new Date(iso).toLocaleDateString("pt-BR", { timeZone: "America/Sao_Paulo" });
const stateOf = (t: ApiToken) => t.revokedAt ? "Revogado" : new Date(t.expiresAt) < new Date() ? "Vencido" : "Ativo";

/** Tokens pessoais de API (Minha conta). O valor aparece uma única vez, logo após criar. */
export default function ApiTokens({ roles }: { roles: Role[] }) {
  const [tokens, setTokens] = useState<ApiToken[]>([]), [notice, setNotice] = useState("");
  const [form, setForm] = useState({ name: "", role: roles[0] ?? "viewer", days: 90 });
  const [created, setCreated] = useState<string | null>(null), [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    const r = await fetch("/api/tokens");
    return r.ok ? (await r.json() as ApiToken[]) : [];
  }, []);
  useEffect(() => { let active = true; load().then(t => { if (active) setTokens(t); }); return () => { active = false; }; }, [load]);

  async function create(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setNotice("");
    const r = await fetch("/api/tokens", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(form) });
    const data = await r.json().catch(() => ({}));
    setBusy(false);
    if (!r.ok) { setNotice(data.error ?? "Não foi possível criar o token."); return; }
    setCreated(data.token); setForm({ ...form, name: "" }); setTokens(await load());
  }
  async function revoke(t: ApiToken) {
    if (!confirm(`Revogar o token "${t.name}"? Integrações que usam este token deixam de funcionar na hora.`)) return;
    const r = await fetch(`/api/tokens/${t.id}`, { method: "DELETE" });
    setNotice(r.ok ? "Token revogado." : (await r.json().catch(() => ({}))).error ?? "Falha ao revogar.");
    setTokens(await load());
  }

  return <section className="account-card">
    <h2><KeySquare size={18}/>Tokens de API</h2>
    <p>Para integrar CI/CD, SIEM ou scripts. O token age em seu nome, com papel Leitor ou Analista, e só acessa ativos, avaliações, escopos, achados e relatórios. Envie no cabeçalho <code>Authorization: Bearer snt_…</code>.</p>
    {notice && <div className="notice" role="status"><span>{notice}</span></div>}
    {created && <div className="token-once" role="status">
      <p><b>Copie o token agora.</b> Ele não será exibido de novo.</p>
      <code>{created}</code>
      <div className="row-actions">
        <button className="button button-secondary" onClick={() => void navigator.clipboard?.writeText(created).then(() => setNotice("Token copiado."))}><Copy size={15}/>Copiar</button>
        <button className="button button-primary" onClick={() => setCreated(null)}>Já guardei</button>
      </div>
    </div>}
    <form className="inline-form" onSubmit={create}>
      <input aria-label="Nome do token" placeholder="Nome (ex.: pipeline de deploy)" required minLength={2} maxLength={80} value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
      <select aria-label="Papel do token" value={form.role} onChange={e => setForm({ ...form, role: e.target.value as Role })}>{roles.map(r => <option key={r} value={r}>{ROLE_LABELS[r]}</option>)}</select>
      <select aria-label="Validade" value={form.days} onChange={e => setForm({ ...form, days: Number(e.target.value) })}>{[7, 30, 90, 365].map(d => <option key={d} value={d}>{d} dias</option>)}</select>
      <button className="button button-primary" disabled={busy}><Plus size={15}/>Criar token</button>
    </form>
    {tokens.length > 0 && <div className="table-scroll"><table className="users-table"><thead><tr><th>Nome</th><th>Papel</th><th>Último uso</th><th>Vence</th><th/></tr></thead><tbody>
      {tokens.map(t => <tr key={t.id}>
        <td>{t.name}<br/><small className="hint"><code>{t.prefix}…</code></small></td>
        <td>{ROLE_LABELS[t.role]}</td>
        <td>{t.lastUsedAt ? `${date(t.lastUsedAt)}${t.lastUsedIp ? ` · ${t.lastUsedIp}` : ""}` : "Nunca"}</td>
        <td>{date(t.expiresAt)}</td>
        <td>{stateOf(t) === "Ativo" ? <button className="run-button" onClick={() => void revoke(t)}>Revogar</button> : stateOf(t)}</td>
      </tr>)}
    </tbody></table></div>}
  </section>;
}
