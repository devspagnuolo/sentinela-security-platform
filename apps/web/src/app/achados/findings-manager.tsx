"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowLeft, X } from "lucide-react";
import { FINDING_STATUS_LABELS, SEVERITY_LABELS } from "@/lib/labels";
import type { Asset, Finding, FindingEvent, FindingStatus, Severity } from "@/lib/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const date = (iso: string | null) => iso ? new Date(iso).toLocaleDateString("pt-BR", { timeZone: "America/Sao_Paulo" }) : "—";
const inDays = (n: number) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10);

export default function FindingsManager({ canTriage, canAccept }: { canTriage: boolean; canAccept: boolean }) {
  const router = useRouter();
  const [findings, setFindings] = useState<Finding[]>([]), [assets, setAssets] = useState<Asset[]>([]);
  const [status, setStatus] = useState<FindingStatus | "">("open"), [severity, setSeverity] = useState<Severity | "">(""), [assetId, setAssetId] = useState("");
  const [selected, setSelected] = useState<Finding | null>(null), [events, setEvents] = useState<FindingEvent[]>([]);
  const [action, setAction] = useState<FindingStatus | null>(null), [reason, setReason] = useState(""), [until, setUntil] = useState(inDays(90));
  const [notice, setNotice] = useState(""), [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const params = new URLSearchParams({ ...(status && { status }), ...(assetId && { assetId }) });
    const [f, a] = await Promise.all([fetch(`/api/findings?${params}`), fetch("/api/assets")]);
    if (f.status === 401) { router.replace("/login"); return null; }
    return { findings: f.ok ? await f.json() as Finding[] : [], assets: a.ok ? await a.json() as Asset[] : [] };
  }, [status, assetId, router]);
  useEffect(() => {
    let active = true;
    load().then(r => { if (active && r) { setFindings(r.findings); setAssets(r.assets); } });
    return () => { active = false; };
  }, [load]);

  const visible = useMemo(() => findings.filter(f => !severity || f.severity === severity).sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)), [findings, severity]);
  const assetName = (id: string) => assets.find(a => a.id === id)?.name ?? "Ativo";

  async function open(f: Finding) {
    setSelected(f); setAction(null); setReason(""); setEvents([]);
    const r = await fetch(`/api/findings/${f.id}/events`);
    if (r.ok) setEvents(await r.json());
  }
  async function triage(e: React.FormEvent) {
    e.preventDefault(); if (!selected || !action) return;
    setBusy(true);
    const r = await fetch(`/api/findings/${selected.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: action, reason, ...(action === "accepted" && { acceptedUntil: until }) }) });
    const data = await r.json();
    setBusy(false);
    if (!r.ok) { setNotice(data.error ?? "Falha na operação."); return; }
    setNotice(`Achado marcado como ${FINDING_STATUS_LABELS[data.status as FindingStatus].toLowerCase()}.`);
    const fresh = await load();
    if (fresh) { setFindings(fresh.findings); setAssets(fresh.assets); }
    await open(data);
  }
  const actions = (f: Finding): FindingStatus[] => f.status === "open"
    ? ["false_positive", "fixed", ...(canAccept ? ["accepted" as const] : [])]
    : ["open", ...(f.status === "accepted" && canAccept ? ["accepted" as const] : [])];

  return <main className="content users-page findings-page">
    <Link className="button button-secondary" href="/"><ArrowLeft size={15}/>Voltar ao painel</Link>
    <h1>Achados</h1>
    <p className="muted">Um achado por problema e ativo. Reavaliações atualizam a evidência, marcam como corrigido o que deixou de aparecer e reabrem o que voltou.</p>
    {notice && <div className="notice" role="status"><span>{notice}</span></div>}
    <div className="row-actions filters">
      <select aria-label="Situação" value={status} onChange={e => setStatus(e.target.value as FindingStatus | "")}>
        <option value="">Todas as situações</option>
        {(Object.keys(FINDING_STATUS_LABELS) as FindingStatus[]).map(s => <option key={s} value={s}>{FINDING_STATUS_LABELS[s]}</option>)}
      </select>
      <select aria-label="Severidade" value={severity} onChange={e => setSeverity(e.target.value as Severity | "")}>
        <option value="">Todas as severidades</option>
        {SEVERITIES.map(s => <option key={s} value={s}>{SEVERITY_LABELS[s]}</option>)}
      </select>
      <select aria-label="Ativo" value={assetId} onChange={e => setAssetId(e.target.value)}>
        <option value="">Todos os ativos</option>
        {assets.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
      </select>
    </div>
    <div className="table-scroll">
      <table className="users-table findings-table"><thead><tr><th>Achado</th><th>Severidade</th><th>Ativo</th><th>Situação</th><th>Visto por último</th></tr></thead><tbody>
        {visible.map(f => <tr key={f.id} className={selected?.id === f.id ? "selected" : undefined} onClick={() => void open(f)} tabIndex={0} onKeyDown={e => { if (e.key === "Enter") void open(f); }}>
          <td><b>{f.title}</b><br/><small className="muted">{f.category}</small></td>
          <td><span className={`severity-tag ${f.severity}`}>{SEVERITY_LABELS[f.severity]}</span></td>
          <td>{assetName(f.assetId)}</td>
          <td><span className={`status-badge status-${f.status}`}>{FINDING_STATUS_LABELS[f.status]}</span>{f.status === "accepted" && <><br/><small className="muted">até {date(f.acceptedUntil)}</small></>}</td>
          <td className="nowrap">{date(f.lastSeenAt)}</td>
        </tr>)}
        {visible.length === 0 && <tr><td colSpan={5} className="muted">Nenhum achado com esses filtros.</td></tr>}
      </tbody></table>
    </div>

    {selected && <aside className="account-card finding-detail" aria-label="Detalhes do achado">
      <div className="scope-head"><h2>{selected.title}</h2><button className="icon-button" aria-label="Fechar" onClick={() => setSelected(null)}><X size={18}/></button></div>
      <p className="muted">{assetName(selected.assetId)} · {SEVERITY_LABELS[selected.severity]} · primeira vez em {date(selected.discoveredAt)} · última em {date(selected.lastSeenAt)}</p>
      <p><b>Observação:</b> {selected.description}</p>
      <p><b>Evidência:</b> {selected.evidence}</p>
      <p><b>Recomendação:</b> {selected.recommendation}</p>
      <p><b>Situação:</b> <span className={`status-badge status-${selected.status}`}>{FINDING_STATUS_LABELS[selected.status]}</span>{selected.statusReason && ` · ${selected.statusReason}`}</p>
      {canTriage && <div className="row-actions">{actions(selected).map(a => <button key={a} className={`button ${action === a ? "button-primary" : "button-secondary"}`} onClick={() => { setAction(a); setReason(""); }}>
        {a === "open" ? "Reabrir" : a === "accepted" ? (selected.status === "accepted" ? "Prorrogar aceite" : "Aceitar risco") : a === "fixed" ? "Marcar corrigido" : "Falso positivo"}
      </button>)}</div>}
      {action && <form className="stack-form" onSubmit={triage}>
        <label>{action === "accepted" ? "Justificativa do aceite (controle compensatório, dono do risco)" : action === "false_positive" ? "Por que é um falso positivo?" : "Comentário (opcional)"}
          <textarea rows={3} required={action === "accepted" || action === "false_positive"} minLength={action === "accepted" || action === "false_positive" ? 5 : undefined} value={reason} onChange={e => setReason(e.target.value)} /></label>
        {action === "accepted" && <label>Aceite válido até<input type="date" required min={inDays(1)} max={inDays(365)} value={until} onChange={e => setUntil(e.target.value)} /></label>}
        <button className="button button-primary" disabled={busy}>Confirmar</button>
      </form>}
      <h3>Histórico</h3>
      {events.length ? <ul className="history">{events.map(ev => <li key={ev.id}><b>{date(ev.createdAt)}</b> · {ev.fromStatus ? `${FINDING_STATUS_LABELS[ev.fromStatus]} → ` : ""}{FINDING_STATUS_LABELS[ev.toStatus]} · {ev.actorName ?? "Sistema"}{ev.reason && `: ${ev.reason}`}</li>)}</ul> : <p className="hint">Sem alterações desde que foi encontrado.</p>}
    </aside>}
  </main>;
}
