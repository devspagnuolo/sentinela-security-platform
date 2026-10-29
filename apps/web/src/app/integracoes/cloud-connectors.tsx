"use client";
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Cloud, Plus, RefreshCw } from "lucide-react";
import type { CloudConnector } from "@/db/connectors";

const when = (iso: string) => new Date(iso).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo", dateStyle: "short", timeStyle: "short" });
type Form = { name: string; provider: "cloudflare" | "aws_route53"; apiToken: string; accessKeyId: string; secretAccessKey: string };
const empty: Form = { name: "", provider: "cloudflare", apiToken: "", accessKeyId: "", secretAccessKey: "" };
const credentialsOf = (f: Form) => f.provider === "cloudflare" ? { provider: f.provider, apiToken: f.apiToken } : { provider: f.provider, accessKeyId: f.accessKeyId, secretAccessKey: f.secretAccessKey };

async function send(url: string, method = "POST", body?: unknown) {
  const r = await fetch(url, { method, headers: { "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
  return { ok: r.ok, data: await r.json().catch(() => ({})) };
}

/** Conectores de nuvem somente leitura: Admin e Owner cadastram; a descoberta aparece em /descoberta. */
export default function CloudConnectors() {
  const [items, setItems] = useState<CloudConnector[]>([]), [form, setForm] = useState<Form>(empty);
  const [notice, setNotice] = useState(""), [busy, setBusy] = useState(false);
  const load = useCallback(async () => { const r = await fetch("/api/connectors"); return r.ok ? await r.json() as CloudConnector[] : []; }, []);
  useEffect(() => { let active = true; load().then(c => { if (active) setItems(c); }); return () => { active = false; }; }, [load]);
  async function run(action: () => Promise<void>) { setBusy(true); setNotice(""); try { await action(); } catch { setNotice("Falha de conexão."); } setBusy(false); setItems(await load()); }
  const summary = (d: { hosts: number; newHosts: number; newOutOfScope: string[] }) => `${d.hosts} hostname(s), ${d.newHosts} novo(s)${d.newOutOfScope.length ? `, ${d.newOutOfScope.length} fora de escopo` : ""}.`;

  const create = (e: React.FormEvent) => { e.preventDefault(); void run(async () => {
    const r = await send("/api/connectors", "POST", { name: form.name, credentials: credentialsOf(form) });
    if (!r.ok) { setNotice(r.data.error ?? "Não foi possível cadastrar."); return; }
    setForm(empty); setNotice(`Conector cadastrado e sincronizado: ${summary(r.data.sync)}`);
  }); };
  const sync = (c: CloudConnector) => run(async () => {
    const r = await send(`/api/connectors/${c.id}/sync`);
    setNotice(r.data.ok ? `${c.name}: ${summary(r.data)}` : r.data.error ?? "Falha na sincronização.");
  });
  const toggle = (c: CloudConnector) => run(async () => {
    const r = await send(`/api/connectors/${c.id}`, "PATCH", { enabled: !c.enabled });
    setNotice(r.ok ? (c.enabled ? `${c.name} desligado.` : `${c.name} religado.`) : r.data.error ?? "Falha na operação.");
  });
  const remove = (c: CloudConnector) => { if (confirm(`Remover o conector ${c.name}? Os hostnames que ele descobriu saem da lista; ativos já cadastrados continuam.`)) void run(async () => {
    const r = await send(`/api/connectors/${c.id}`, "DELETE");
    setNotice(r.ok ? "Conector removido." : r.data.error ?? "Falha na operação.");
  }); };

  return <section className="account-card">
    <h2><Cloud size={18}/>Conectores de nuvem (somente leitura)</h2>
    <p>Liste as zonas DNS do cliente para descobrir hostnames expostos e comparar com os escopos autorizados. O conector só lê: crie uma credencial com permissão de leitura de DNS e nada mais. Descobrir um hostname não autoriza avaliá-lo. Veja a <Link href="/descoberta">descoberta</Link> e as permissões mínimas em <a href="https://github.com/devspagnuolo/sentinela-security-platform/blob/main/docs/conectores.md" target="_blank" rel="noopener noreferrer">docs/conectores.md</a>.</p>
    {notice && <div className="notice" role="status"><span>{notice}</span></div>}
    <form className="sso-form" onSubmit={create}>
      <label>Provedor
        <select value={form.provider} onChange={e => setForm({ ...form, provider: e.target.value as Form["provider"] })}>
          <option value="cloudflare">Cloudflare (DNS)</option>
          <option value="aws_route53">AWS Route 53</option>
        </select>
      </label>
      <label>Nome<input required minLength={2} maxLength={80} placeholder="Ex.: DNS do cliente Loja" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /></label>
      {form.provider === "cloudflare" ? <label>API token<input type="password" autoComplete="off" required value={form.apiToken} onChange={e => setForm({ ...form, apiToken: e.target.value })} />
        <span className="hint">Token com Zone → Zone → Read e Zone → DNS → Read, só nas zonas do cliente.</span></label>
      : <>
        <label>Access key ID<input autoComplete="off" required placeholder="AKIA…" value={form.accessKeyId} onChange={e => setForm({ ...form, accessKeyId: e.target.value })} /></label>
        <label>Secret access key<input type="password" autoComplete="off" required value={form.secretAccessKey} onChange={e => setForm({ ...form, secretAccessKey: e.target.value })} />
          <span className="hint">Usuário IAM só com route53:ListHostedZones e route53:ListResourceRecordSets.</span></label>
      </>}
      <button className="button button-primary" disabled={busy}><Plus size={15}/>Cadastrar e sincronizar</button>
    </form>
    {items.length > 0 && <div className="table-scroll"><table className="users-table"><thead><tr><th>Conector</th><th>Credencial</th><th>Última sincronização</th><th>Hostnames</th><th/></tr></thead><tbody>
      {items.map(c => <tr key={c.id}>
        <td>{c.name}<br/><small className="hint">{c.providerLabel}{!c.enabled && " · desligado"}</small></td>
        <td><code>{c.credentialHint}</code></td>
        <td>{c.lastSyncAt ? when(c.lastSyncAt) : "Nunca"}{c.lastError && <><br/><small className="hint">{c.lastError}</small></>}</td>
        <td>{c.hostCount ?? "—"}{c.zoneCount !== null && <small className="hint"> em {c.zoneCount} zona(s)</small>}</td>
        <td className="nowrap">
          <button className="run-button" disabled={busy} onClick={() => void sync(c)}><RefreshCw size={13}/>Sincronizar</button>{" "}
          <button className="run-button" disabled={busy} onClick={() => void toggle(c)}>{c.enabled ? "Desligar" : "Religar"}</button>{" "}
          <button className="run-button" disabled={busy} onClick={() => remove(c)}>Remover</button>
        </td>
      </tr>)}
    </tbody></table></div>}
  </section>;
}
