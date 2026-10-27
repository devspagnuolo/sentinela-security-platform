"use client";
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowLeft, Check, Plus, ShieldOff } from "lucide-react";
import { SCOPE_STATE_LABELS } from "@/lib/labels";
import type { Authorization } from "@/lib/types";

type Props = { currentUserId: string; isOwner: boolean; canWrite: boolean; canApprove: boolean };
const emptyForm = { reference: "", clientName: "", hostnames: "", excludedHostnames: "", validFrom: "", validUntil: "", emergencyContact: "", notes: "" };
const lines = (text: string) => text.split(/[\s,;]+/).map(s => s.trim()).filter(Boolean);
const date = (iso: string | null) => iso ? new Date(iso).toLocaleDateString("pt-BR", { timeZone: "America/Sao_Paulo" }) : "—";

export default function ScopesManager({ currentUserId, isOwner, canWrite, canApprove }: Props) {
  const router = useRouter();
  const [scopes, setScopes] = useState<Authorization[]>([]), [notice, setNotice] = useState("");
  const [form, setForm] = useState(emptyForm), [creating, setCreating] = useState(false), [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    const r = await fetch("/api/scopes");
    if (r.status === 401) { router.replace("/login"); return []; }
    return r.ok ? (await r.json() as Authorization[]) : [];
  }, [router]);
  useEffect(() => { let active = true; load().then(s => { if (active) setScopes(s); }); return () => { active = false; }; }, [load]);

  async function send(url: string, body: unknown, ok: string) {
    setBusy(true);
    const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const data = await r.json().catch(() => ({}));
    setNotice(r.ok ? ok : data.error ?? "Falha na operação.");
    if (r.ok) setScopes(await load());
    setBusy(false);
    return r.ok;
  }
  async function create(e: React.FormEvent) {
    e.preventDefault();
    const ok = await send("/api/scopes", { ...form, hostnames: lines(form.hostnames), excludedHostnames: lines(form.excludedHostnames), validFrom: form.validFrom || undefined }, "Autorização cadastrada. Ela passa a valer depois de aprovada por um Admin ou Owner.");
    if (ok) { setForm(emptyForm); setCreating(false); }
  }
  const revoke = (s: Authorization) => {
    const reason = prompt(`Motivo da revogação de ${s.reference}? Avaliações dos ativos vinculados serão bloqueadas imediatamente.`);
    if (reason) void send(`/api/scopes/${s.id}/revoke`, { reason }, "Autorização revogada.");
  };
  const canApproveThis = (s: Authorization) => canApprove && s.status === "pending" && (s.createdBy?.id !== currentUserId || isOwner);

  return <main className="content users-page scopes-page">
    <Link className="button button-secondary" href="/"><ArrowLeft size={15}/>Voltar ao painel</Link>
    <h1>Escopos e autorizações</h1>
    <p className="muted">Cada ativo precisa estar coberto por uma autorização aprovada e dentro da validade. O scanner confere a autorização antes de cada avaliação.</p>
    {notice && <div className="notice" role="status"><span>{notice}</span></div>}
    {canWrite && !creating && <button className="button button-primary" onClick={() => setCreating(true)}><Plus size={15}/>Nova autorização</button>}
    {creating && <form className="account-card scope-form" onSubmit={create}>
      <h2>Nova autorização de escopo</h2>
      <div className="form-grid">
        <label>Referência do documento<input required placeholder="Contrato, termo ou chamado (ex.: CT-2026-07)" value={form.reference} onChange={e => setForm({ ...form, reference: e.target.value })} /></label>
        <label>Cliente<input placeholder="Nome do cliente" value={form.clientName} onChange={e => setForm({ ...form, clientName: e.target.value })} /></label>
        <label>Início da validade<input type="date" value={form.validFrom} onChange={e => setForm({ ...form, validFrom: e.target.value })} /></label>
        <label>Fim da validade<input type="date" required value={form.validUntil} onChange={e => setForm({ ...form, validUntil: e.target.value })} /></label>
      </div>
      <label>Hostnames autorizados (um por linha; *.dominio.com cobre subdomínios)<textarea required rows={3} placeholder={"app.cliente.com.br\n*.api.cliente.com.br"} value={form.hostnames} onChange={e => setForm({ ...form, hostnames: e.target.value })} /></label>
      <label>Exclusões (hostnames fora do escopo)<textarea rows={2} placeholder="legado.api.cliente.com.br" value={form.excludedHostnames} onChange={e => setForm({ ...form, excludedHostnames: e.target.value })} /></label>
      <label>Contato de emergência<input placeholder="Nome, telefone ou e-mail do responsável do cliente" value={form.emergencyContact} onChange={e => setForm({ ...form, emergencyContact: e.target.value })} /></label>
      <label>Observações e restrições<textarea rows={2} placeholder="Janelas de horário, limites acordados…" value={form.notes} onChange={e => setForm({ ...form, notes: e.target.value })} /></label>
      <div className="row-actions">
        <button className="button button-primary" disabled={busy}>Cadastrar</button>
        <button type="button" className="button button-secondary" onClick={() => setCreating(false)}>Cancelar</button>
      </div>
    </form>}
    <div className="scope-list">
      {scopes.map(s => <article key={s.id} className="account-card scope-card">
        <div className="scope-head">
          <div><h2>{s.reference}{s.clientName && <span className="muted"> · {s.clientName}</span>}</h2>
            <p className="muted">Validade: {s.validFrom ? `de ${date(s.validFrom)}` : "desde a aprovação"} até {date(s.validUntil)} · {s.assetCount} ativo(s)</p></div>
          <span className={`state-badge state-${s.state}`}>{SCOPE_STATE_LABELS[s.state]}</span>
        </div>
        <p><b>Hostnames:</b> {s.hostnames.join(", ")}</p>
        {s.excludedHostnames.length > 0 && <p><b>Exclusões:</b> {s.excludedHostnames.join(", ")}</p>}
        {s.emergencyContact && <p><b>Contato de emergência:</b> {s.emergencyContact}</p>}
        {s.notes && <p><b>Observações:</b> {s.notes}</p>}
        <p className="hint">Cadastrada por {s.createdBy?.name ?? "—"}{s.approvedBy && ` · aprovada por ${s.approvedBy.name} em ${date(s.approvedAt)}`}{s.revokedAt && ` · revogada em ${date(s.revokedAt)}: ${s.revokeReason}`}</p>
        {canApprove && s.status !== "revoked" && <div className="row-actions">
          {canApproveThis(s) && <button className="button button-primary" disabled={busy} onClick={() => void send(`/api/scopes/${s.id}/approve`, {}, `Autorização ${s.reference} aprovada.`)}><Check size={15}/>Aprovar</button>}
          {s.status === "pending" && !canApproveThis(s) && <span className="hint">Aguardando aprovação de outra pessoa.</span>}
          <button className="button button-secondary" disabled={busy} onClick={() => revoke(s)}><ShieldOff size={15}/>Revogar</button>
        </div>}
      </article>)}
      {scopes.length === 0 && <p className="muted">Nenhuma autorização cadastrada.</p>}
    </div>
  </main>;
}
