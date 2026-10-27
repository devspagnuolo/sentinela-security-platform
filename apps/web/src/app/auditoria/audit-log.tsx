"use client";
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowLeft, Download } from "lucide-react";
import type { AuditEntry } from "@/db/repository";
import { actionLabel, AUDIT_CATEGORIES } from "@/lib/audit";

const PAGE = 50;

function details(metadata: Record<string, unknown>) {
  return Object.entries(metadata).filter(([, v]) => v !== null && v !== undefined && v !== "")
    .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`).join(" · ").slice(0, 240);
}

export default function AuditLog() {
  const router = useRouter();
  const [category, setCategory] = useState(""), [entries, setEntries] = useState<AuditEntry[]>([]);
  const [more, setMore] = useState(false), [loading, setLoading] = useState(true);
  const fetchPage = useCallback(async (before?: number) => {
    const params = new URLSearchParams({ limit: String(PAGE), ...(category && { category }), ...(before !== undefined && { before: String(before) }) });
    const r = await fetch(`/api/audit?${params}`);
    if (r.status === 401) { router.replace("/login"); return []; }
    return r.ok ? (await r.json() as AuditEntry[]) : [];
  }, [category, router]);
  useEffect(() => {
    let active = true;
    fetchPage().then(page => { if (active) { setEntries(page); setMore(page.length === PAGE); setLoading(false); } });
    return () => { active = false; };
  }, [fetchPage]);
  async function loadMore() {
    setLoading(true);
    const page = await fetchPage(entries.at(-1)?.seq);
    setEntries([...entries, ...page]); setMore(page.length === PAGE); setLoading(false);
  }

  return <main className="content users-page audit-page">
    <Link className="button button-secondary" href="/"><ArrowLeft size={15}/>Voltar ao painel</Link>
    <h1>Auditoria</h1>
    <p className="muted">Registro imutável de acessos e alterações da organização, do mais recente ao mais antigo.</p>
    <div className="row-actions">
      <select aria-label="Categoria" value={category} onChange={e => { setLoading(true); setCategory(e.target.value); }}>
        <option value="">Todas as categorias</option>
        {Object.entries(AUDIT_CATEGORIES).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
      </select>
      <a className="button button-secondary" href={`/api/audit?format=csv${category ? `&category=${category}` : ""}`}><Download size={15}/>Exportar CSV</a>
    </div>
    <div className="table-scroll">
      <table className="users-table"><thead><tr><th>Quando</th><th>Evento</th><th>Autor</th><th>Detalhes</th></tr></thead><tbody>
        {entries.map(e => <tr key={e.id}>
          <td className="nowrap">{new Date(e.createdAt).toLocaleString("pt-BR")}</td>
          <td><b>{actionLabel(e.action)}</b><br/><small className="muted">{e.action}</small></td>
          <td>{e.actorName ?? <span className="muted">Sistema / anônimo</span>}{e.actorEmail && <><br/><small className="muted">{e.actorEmail}</small></>}</td>
          <td className="audit-details">{details(e.metadata)}</td>
        </tr>)}
        {!loading && entries.length === 0 && <tr><td colSpan={4} className="muted">Nenhum evento nesta categoria.</td></tr>}
      </tbody></table>
    </div>
    {more && <button className="button button-secondary" disabled={loading} onClick={() => void loadMore()}>{loading ? "Carregando…" : "Carregar mais"}</button>}
  </main>;
}
