"use client";
import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { TECHNOLOGY_CATEGORY_LABELS, technologyCategoryLabel, type TechnologyCategory } from "@/lib/labels";
import type { AssetTechnology } from "@/lib/types";

const date = (iso: string) => new Date(iso).toLocaleDateString("pt-BR", { timeZone: "America/Sao_Paulo" });
type Group = { key: string; category: string; name: string; versions: string[]; uses: AssetTechnology[]; lastSeenAt: string };

/** Agrupa por tecnologia: quais ativos a usam e quais versões eles anunciam. */
function group(rows: AssetTechnology[]): Group[] {
  const groups = new Map<string, Group>();
  for (const t of rows) {
    const key = `${t.category}:${t.name}`;
    const g = groups.get(key) ?? { key, category: t.category, name: t.name, versions: [], uses: [], lastSeenAt: t.lastSeenAt };
    if (t.version && !g.versions.includes(t.version)) g.versions.push(t.version);
    g.uses.push(t);
    if (t.lastSeenAt > g.lastSeenAt) g.lastSeenAt = t.lastSeenAt;
    groups.set(key, g);
  }
  return [...groups.values()].sort((a, b) => b.uses.length - a.uses.length || a.name.localeCompare(b.name));
}

export default function InventoryManager() {
  const router = useRouter();
  const [rows, setRows] = useState<AssetTechnology[] | null>(null);
  const [category, setCategory] = useState(""), [assetId, setAssetId] = useState(""), [stale, setStale] = useState(false);
  useEffect(() => {
    let active = true;
    fetch("/api/technologies?includeStale=1").then(async r => {
      if (r.status === 401) { router.replace("/login"); return; }
      if (active) setRows(r.ok ? await r.json() : []);
    });
    return () => { active = false; };
  }, [router]);

  const assets = useMemo(() => [...new Map((rows ?? []).map(t => [t.assetId, t.assetName])).entries()].sort((a, b) => a[1].localeCompare(b[1])), [rows]);
  const groups = useMemo(() => group((rows ?? []).filter(t => (stale || t.current) && (!category || t.category === category) && (!assetId || t.assetId === assetId))), [rows, stale, category, assetId]);
  const covered = new Set((rows ?? []).filter(t => t.current).map(t => t.assetId)).size;

  return <main className="content users-page inventory-page">
    <Link className="button button-secondary" href="/"><ArrowLeft size={15}/>Voltar ao painel</Link>
    <h1>Inventário de tecnologias</h1>
    <p className="muted">O que cada ativo anuncia nos cabeçalhos HTTP, nos nomes de cookies, no certificado e no DNS, coletado na própria avaliação, sem requisições extras. É indicativo: uma CDN na frente esconde o servidor de origem, e banners podem ser alterados.</p>
    {rows && <p className="hint">{covered} ativo(s) com inventário. O inventário é atualizado a cada avaliação concluída.</p>}
    <div className="row-actions filters">
      <select aria-label="Categoria" value={category} onChange={e => setCategory(e.target.value)}>
        <option value="">Todas as categorias</option>
        {(Object.keys(TECHNOLOGY_CATEGORY_LABELS) as TechnologyCategory[]).map(c => <option key={c} value={c}>{TECHNOLOGY_CATEGORY_LABELS[c]}</option>)}
      </select>
      <select aria-label="Ativo" value={assetId} onChange={e => setAssetId(e.target.value)}>
        <option value="">Todos os ativos</option>
        {assets.map(([id, name]) => <option key={id} value={id}>{name}</option>)}
      </select>
      <label className="checkbox-label"><input type="checkbox" checked={stale} onChange={e => setStale(e.target.checked)} /> Incluir o que não apareceu na última avaliação</label>
    </div>
    <div className="table-scroll">
      <table className="users-table"><thead><tr><th>Tecnologia</th><th>Categoria</th><th>Versões anunciadas</th><th>Ativos</th><th>Vista por último</th></tr></thead><tbody>
        {groups.map(g => <tr key={g.key}>
          <td><b>{g.name}</b></td>
          <td>{technologyCategoryLabel(g.category)}</td>
          <td>{g.versions.length ? g.versions.join(", ") : <span className="muted">Não anunciada</span>}</td>
          <td>{g.uses.map((t, i) => <span key={t.id} title={t.evidence}>{i > 0 && ", "}{t.assetName}{t.version && g.versions.length > 1 ? ` (${t.version})` : ""}{!t.current && <small className="muted"> (antes)</small>}</span>)}</td>
          <td className="nowrap">{date(g.lastSeenAt)}</td>
        </tr>)}
        {rows && groups.length === 0 && <tr><td colSpan={5} className="muted">{rows.length ? "Nenhuma tecnologia com esses filtros." : "Nenhuma tecnologia identificada ainda. O inventário aparece depois da primeira avaliação concluída de cada ativo."}</td></tr>}
      </tbody></table>
    </div>
  </main>;
}
