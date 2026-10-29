"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowLeft, Plus } from "lucide-react";
import type { DiscoveredHost, DiscoveryStatus } from "@/db/connectors";

const STATUS: Record<DiscoveryStatus, { label: string; className: string; hint: string }> = {
  out_of_scope: { label: "Fora de escopo", className: "status-open", hint: "Nenhum escopo vigente cobre este hostname. Confirme com o cliente se faz parte do contrato antes de qualquer avaliação." },
  in_scope: { label: "Coberto por escopo", className: "status-accepted", hint: "Um escopo vigente cobre o hostname, mas ele ainda não é um ativo." },
  asset: { label: "Já é ativo", className: "status-fixed", hint: "Já cadastrado como ativo." },
  internal: { label: "IP interno", className: "status-false_positive", hint: "Só aponta para endereços privados; não é alcançável pela internet." }
};
const ORDER: DiscoveryStatus[] = ["out_of_scope", "in_scope", "asset", "internal"];
const date = (iso: string) => new Date(iso).toLocaleDateString("pt-BR", { timeZone: "America/Sao_Paulo" });

export default function DiscoveryManager({ canAddAsset, canManageConnectors }: { canAddAsset: boolean; canManageConnectors: boolean }) {
  const router = useRouter();
  const [hosts, setHosts] = useState<DiscoveredHost[] | null>(null), [status, setStatus] = useState<DiscoveryStatus | "">(""), [query, setQuery] = useState("");
  const [notice, setNotice] = useState(""), [busy, setBusy] = useState<string | null>(null);
  const load = useCallback(async () => {
    const r = await fetch("/api/discovery");
    if (r.status === 401) { router.replace("/login"); return []; }
    return r.ok ? await r.json() as DiscoveredHost[] : [];
  }, [router]);
  useEffect(() => { let active = true; load().then(h => { if (active) setHosts(h); }); return () => { active = false; }; }, [load]);

  const counts = useMemo(() => Object.fromEntries(ORDER.map(s => [s, (hosts ?? []).filter(h => h.status === s).length])) as Record<DiscoveryStatus, number>, [hosts]);
  const visible = useMemo(() => (hosts ?? []).filter(h => (!status || h.status === status) && (!query || h.hostname.includes(query.trim().toLowerCase())))
    .sort((a, b) => ORDER.indexOf(a.status) - ORDER.indexOf(b.status) || a.hostname.localeCompare(b.hostname)), [hosts, status, query]);

  async function addAsset(h: DiscoveredHost) {
    if (!h.authorization) return;
    setBusy(h.id); setNotice("");
    const r = await fetch("/api/assets", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: h.hostname, url: `https://${h.hostname}`, kind: "Web application", owner: h.connector.name, authorizationId: h.authorization.id }) });
    const data = await r.json().catch(() => ({}));
    setNotice(r.ok ? `${h.hostname} cadastrado como ativo sob ${h.authorization.reference}.` : data.error ?? "Não foi possível cadastrar.");
    setHosts(await load()); setBusy(null);
  }

  return <main className="content users-page inventory-page">
    <Link className="button button-secondary" href="/"><ArrowLeft size={15}/>Voltar ao painel</Link>
    <h1>Descoberta pela nuvem</h1>
    <p className="muted">Hostnames encontrados nas zonas DNS dos conectores de nuvem, comparados com os ativos e os escopos aprovados. Descobrir um hostname não autoriza avaliá-lo: só o que estiver coberto por um escopo vigente pode virar ativo.</p>
    {notice && <div className="notice" role="status"><span>{notice}</span></div>}
    {hosts && hosts.length === 0 ? <p className="hint">Nenhum hostname descoberto ainda. {canManageConnectors ? <>Cadastre um conector em <Link href="/integracoes">Integrações</Link>.</> : "Peça a um Admin para cadastrar um conector de nuvem."}</p> : <>
      <div className="row-actions filters">
        {ORDER.map(s => <button key={s} className={`button ${status === s ? "button-primary" : "button-secondary"}`} onClick={() => setStatus(status === s ? "" : s)}>{STATUS[s].label}: {counts[s]}</button>)}
        <input aria-label="Buscar hostname" placeholder="Buscar hostname" value={query} onChange={e => setQuery(e.target.value)} />
      </div>
      {status && <p className="hint">{STATUS[status].hint}</p>}
      <div className="table-scroll">
        <table className="users-table"><thead><tr><th>Hostname</th><th>Aponta para</th><th>Origem</th><th>Situação</th><th>Visto desde</th><th/></tr></thead><tbody>
          {visible.map(h => <tr key={h.id}>
            <td><b>{h.hostname}</b><br/><small className="muted">zona {h.zone}</small></td>
            <td><small>{h.recordTypes.join(", ")}: {h.targets.slice(0, 3).join(", ")}{h.targets.length > 3 ? "…" : ""}</small></td>
            <td>{h.connector.name}</td>
            <td><span className={`status-badge ${STATUS[h.status].className}`} title={STATUS[h.status].hint}>{STATUS[h.status].label}</span>{h.authorization && h.status === "in_scope" && <><br/><small className="muted">{h.authorization.reference}</small></>}</td>
            <td className="nowrap">{date(h.firstSeenAt)}</td>
            <td>{canAddAsset && h.status === "in_scope" && <button className="run-button" disabled={busy !== null} onClick={() => void addAsset(h)}><Plus size={13}/>Cadastrar ativo</button>}
              {h.status === "out_of_scope" && <Link className="run-button" href="/escopos">Ver escopos</Link>}</td>
          </tr>)}
          {visible.length === 0 && <tr><td colSpan={6} className="muted">Nenhum hostname com esses filtros.</td></tr>}
        </tbody></table>
      </div>
    </>}
  </main>;
}
