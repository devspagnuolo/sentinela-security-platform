"use client";
import { useState } from "react";
import { Archive, Download } from "lucide-react";
import { AUDIT_RETENTION_OPTIONS, CONTACT_RETENTION_OPTIONS, DATA_RETENTION_OPTIONS, retentionLabel, type RetentionSettings } from "@/lib/retention-options";

/** Prazos de retenção e exportação completa da organização (Owner). */
export function RetentionSettingsCard({ initial }: { initial: RetentionSettings }) {
  const [form, setForm] = useState(initial), [notice, setNotice] = useState(""), [busy, setBusy] = useState(false);
  const choice = (key: keyof RetentionSettings, options: readonly number[], keep: boolean) =>
    <select value={form[key] ?? ""} onChange={e => setForm({ ...form, [key]: e.target.value === "" ? null : Number(e.target.value) })}>
      {options.map(d => <option key={d} value={d}>{retentionLabel(d)}</option>)}
      {keep && <option value="">{retentionLabel(null)}</option>}
    </select>;
  async function save(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setNotice("");
    try {
      const r = await fetch("/api/organization/retention", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(form) });
      const data = await r.json();
      if (r.ok) { setForm(data); setNotice("Prazos salvos. A próxima limpeza roda em até uma hora."); }
      else setNotice(data.error ?? "Não foi possível salvar.");
    } catch { setNotice("Falha de conexão."); }
    setBusy(false);
  }
  return <section className="account-card">
    <h2><Archive size={18}/>Retenção de dados (LGPD)</h2>
    <p>Por quanto tempo o Sentinela guarda cada tipo de dado. O que passa do prazo é apagado de vez, de hora em hora. A última avaliação concluída de cada ativo é sempre mantida.</p>
    {notice && <div className="notice" role="status"><span>{notice}</span></div>}
    <form className="sso-form" onSubmit={save}>
      <label>Trilha de auditoria{choice("auditRetentionDays", AUDIT_RETENTION_OPTIONS, false)}<span className="hint">Mínimo de 6 meses, como pede o Marco Civil para registros de acesso.</span></label>
      <label>Avaliações antigas (execuções e evidências){choice("assessmentRetentionDays", DATA_RETENTION_OPTIONS, true)}</label>
      <label>Achados corrigidos ou falsos positivos{choice("closedFindingRetentionDays", DATA_RETENTION_OPTIONS, true)}<span className="hint">Contado da data da triagem. Achados abertos ou com risco aceito nunca são apagados.</span></label>
      <label>Contato de emergência dos escopos encerrados{choice("scopeContactRetentionDays", CONTACT_RETENTION_OPTIONS, false)}<span className="hint">Contado da revogação ou do vencimento do escopo.</span></label>
      <button className="button button-primary" disabled={busy}>Salvar prazos</button>
    </form>
    <p>Para levar os dados a outro sistema, ou guardar uma cópia antes de encerrar o uso, exporte tudo em JSON (sem senhas nem segredos).</p>
    <a className="button button-secondary" href="/api/organization/export" download><Download size={15}/>Exportar dados da organização</a>
  </section>;
}

/** Acesso aos próprios dados (art. 18 da LGPD). */
export function PersonalDataCard() {
  return <section className="account-card">
    <h2><Download size={18}/>Privacidade e dados</h2>
    <p>Baixe em JSON tudo que o Sentinela guarda sobre você: perfil, organizações, sessões com IP e navegador, tokens de API, vínculos de SSO, avisos e o histórico das suas ações.</p>
    <a className="button button-secondary" href="/api/auth/export-data" download><Download size={15}/>Baixar meus dados</a>
    <p className="hint">Para corrigir seu nome ou pedir a remoção dos seus dados, fale com um Owner da organização.</p>
  </section>;
}
