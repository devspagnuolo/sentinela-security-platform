"use client";
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowLeft, Copy, Mail, Plus, Send, Webhook as WebhookIcon } from "lucide-react";
import type { ApiToken } from "@/lib/auth/tokens";
import { ROLE_LABELS } from "@/lib/auth/rbac";
import type { Webhook, WebhookDelivery } from "@/db/webhooks";
import { WEBHOOK_EVENT_TYPES, WEBHOOK_EVENTS, type WebhookEvent } from "@/lib/webhook-events";

const when = (iso: string) => new Date(iso).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo", dateStyle: "short", timeStyle: "short" });
const DELIVERY_LABELS = { pending: "Aguardando", delivered: "Entregue", failed: "Falhou" } as const;
const eventLabel = (e: string) => WEBHOOK_EVENTS[e as WebhookEvent] ?? (e === "webhook.test" ? "Teste" : e);

async function send(url: string, method = "POST", body?: unknown) {
  const r = await fetch(url, { method, headers: { "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
  return { ok: r.ok, status: r.status, data: await r.json().catch(() => ({})) };
}

export default function IntegrationsManager({ canManageTokens, mail }: { canManageTokens: boolean; mail: { from: string; server: string } | null }) {
  const router = useRouter();
  const [hooks, setHooks] = useState<Webhook[]>([]), [tokens, setTokens] = useState<ApiToken[]>([]);
  const [notice, setNotice] = useState(""), [secret, setSecret] = useState<{ name: string; value: string } | null>(null);
  const [form, setForm] = useState<{ name: string; url: string; events: WebhookEvent[] }>({ name: "", url: "", events: [...WEBHOOK_EVENT_TYPES] });
  const [open, setOpen] = useState<string | null>(null), [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const r = await fetch("/api/webhooks");
    if (r.status === 401) { router.replace("/login"); return { hooks: [], tokens: [] }; }
    const t = canManageTokens ? await fetch("/api/tokens?scope=all") : null;
    return { hooks: r.ok ? await r.json() as Webhook[] : [], tokens: t?.ok ? await t.json() as ApiToken[] : [] };
  }, [router, canManageTokens]);
  const refresh = async () => { const d = await load(); setHooks(d.hooks); setTokens(d.tokens); };
  useEffect(() => { let active = true; load().then(d => { if (active) { setHooks(d.hooks); setTokens(d.tokens); } }); return () => { active = false; }; }, [load]);

  async function showDeliveries(id: string) {
    if (open === id) { setOpen(null); return; }
    const r = await send(`/api/webhooks/${id}`, "GET");
    setDeliveries(r.ok ? r.data.deliveries : []); setOpen(id);
  }
  async function run(action: () => Promise<void>) { setBusy(true); setNotice(""); try { await action(); } catch { setNotice("Falha de conexão."); } setBusy(false); }

  const create = (e: React.FormEvent) => { e.preventDefault(); void run(async () => {
    const r = await send("/api/webhooks", "POST", form);
    if (!r.ok) { setNotice(r.data.error ?? "Não foi possível cadastrar."); return; }
    setSecret({ name: r.data.webhook.name, value: r.data.secret }); setForm({ name: "", url: "", events: [...WEBHOOK_EVENT_TYPES] }); await refresh();
  }); };
  const test = (h: Webhook) => run(async () => {
    const r = await send(`/api/webhooks/${h.id}/test`);
    if (!r.ok) { setNotice(r.data.error ?? "Falha no teste."); return; }
    setNotice(r.data.status === "delivered" ? `Teste entregue a ${h.name} (HTTP ${r.data.responseStatus}).` : `Teste não entregue: ${r.data.lastError}`);
    await refresh(); if (open === h.id) { setOpen(null); await showDeliveries(h.id); }
  });
  const toggle = (h: Webhook) => run(async () => {
    const r = await send(`/api/webhooks/${h.id}`, "PATCH", { enabled: !h.enabled });
    setNotice(r.ok ? (h.enabled ? `${h.name} desligado.` : `${h.name} religado.`) : r.data.error ?? "Falha na operação."); await refresh();
  });
  const rotate = (h: Webhook) => { if (confirm(`Trocar o segredo de ${h.name}? O destino precisa ser atualizado com o novo segredo, senão vai recusar as próximas entregas.`)) void run(async () => {
    const r = await send(`/api/webhooks/${h.id}/rotate`);
    if (r.ok) setSecret({ name: h.name, value: r.data.secret }); else setNotice(r.data.error ?? "Falha na operação.");
  }); };
  const remove = (h: Webhook) => { if (confirm(`Remover o webhook ${h.name}? Entregas pendentes serão descartadas.`)) void run(async () => {
    const r = await send(`/api/webhooks/${h.id}`, "DELETE");
    setNotice(r.ok ? "Webhook removido." : r.data.error ?? "Falha na operação."); await refresh();
  }); };
  const revokeToken = (t: ApiToken) => { if (confirm(`Revogar o token "${t.name}" de ${t.user.name}?`)) void run(async () => {
    const r = await send(`/api/tokens/${t.id}`, "DELETE");
    setNotice(r.ok ? "Token revogado." : r.data.error ?? "Falha na operação."); await refresh();
  }); };
  const testEmail = () => run(async () => {
    const r = await send("/api/integrations/email-test");
    setNotice(r.ok ? `E-mail de teste enviado para ${r.data.to}.` : r.data.error ?? "Falha no envio.");
  });
  const toggleEvent = (e: WebhookEvent) => setForm(f => ({ ...f, events: f.events.includes(e) ? f.events.filter(x => x !== e) : [...f.events, e] }));

  return <main className="content integrations-page">
    <Link className="button button-secondary" href="/"><ArrowLeft size={15}/>Voltar ao painel</Link>
    <h1>Integrações</h1>
    <p className="muted">Webhooks avisam outros sistemas (chat, chamados, SIEM) quando algo acontece. Cada entrega é assinada com HMAC-SHA256; veja como validar em <a href="https://github.com/devspagnuolo/sentinela-security-platform/blob/main/docs/api.md" target="_blank" rel="noopener noreferrer">docs/api.md</a>.</p>
    {notice && <div className="notice" role="status"><span>{notice}</span><button onClick={() => setNotice("")} aria-label="Fechar">×</button></div>}
    {secret && <div className="token-once" role="status">
      <p><b>Segredo de assinatura de {secret.name}.</b> Configure no destino agora; ele não será exibido de novo.</p>
      <code>{secret.value}</code>
      <div className="row-actions">
        <button className="button button-secondary" onClick={() => void navigator.clipboard?.writeText(secret.value).then(() => setNotice("Segredo copiado."))}><Copy size={15}/>Copiar</button>
        <button className="button button-primary" onClick={() => setSecret(null)}>Já configurei</button>
      </div>
    </div>}

    <section className="account-card">
      <h2><Mail size={18}/>E-mail</h2>
      {mail ? <>
        <p>Os avisos do sino também são enviados por e-mail a quem não desativou em Minha conta. Remetente <code>{mail.from}</code> via <code>{mail.server}</code>.</p>
        <button className="button button-secondary" disabled={busy} onClick={() => void testEmail()}><Send size={15}/>Enviar e-mail de teste para mim</button>
      </> : <p>Não configurado. Para enviar os avisos também por e-mail, defina <code>SENTINELA_SMTP_URL</code> e <code>SENTINELA_MAIL_FROM</code> no servidor (veja docs/api.md).</p>}
    </section>

    <section className="account-card">
      <h2><WebhookIcon size={18}/>Novo webhook</h2>
      <form className="webhook-form" onSubmit={create}>
        <div className="inline-form">
          <input aria-label="Nome" placeholder="Nome (ex.: canal #seguranca)" required minLength={2} maxLength={80} value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
          <input aria-label="URL" type="url" placeholder="https://hooks.exemplo.com/sentinela" required value={form.url} onChange={e => setForm({ ...form, url: e.target.value })} />
        </div>
        <fieldset className="event-picker"><legend>Eventos</legend>
          {WEBHOOK_EVENT_TYPES.map(e => <label key={e}><input type="checkbox" checked={form.events.includes(e)} onChange={() => toggleEvent(e)} />{WEBHOOK_EVENTS[e]} <code>{e}</code></label>)}
        </fieldset>
        <button className="button button-primary" disabled={busy || !form.events.length}><Plus size={15}/>Cadastrar</button>
      </form>
    </section>

    {hooks.length === 0 ? <p className="muted">Nenhum webhook cadastrado.</p> : hooks.map(h => <section className="account-card" key={h.id}>
      <h2>{h.name} <span className={`pill ${h.enabled ? "pill-ok" : "pill-off"}`}>{h.enabled ? "Ativo" : "Desligado"}</span></h2>
      <p><code>{h.url}</code></p>
      <p className="hint">{h.events.map(eventLabel).join(" · ")}</p>
      {h.disabledReason && <p className="hint">{h.disabledReason}</p>}
      <p className="hint">{h.lastDelivery ? `Última entrega: ${DELIVERY_LABELS[h.lastDelivery.status]}${h.lastDelivery.responseStatus ? ` (HTTP ${h.lastDelivery.responseStatus})` : ""} em ${when(h.lastDelivery.at)}` : "Nenhuma entrega ainda."}</p>
      <div className="row-actions">
        <button className="run-button" disabled={busy} onClick={() => void test(h)}><Send size={13}/>Testar</button>
        <button className="run-button" disabled={busy} onClick={() => void toggle(h)}>{h.enabled ? "Desligar" : "Religar"}</button>
        <button className="run-button" disabled={busy} onClick={() => rotate(h)}>Trocar segredo</button>
        <button className="run-button" onClick={() => void showDeliveries(h.id)}>{open === h.id ? "Ocultar entregas" : "Entregas"}</button>
        <button className="run-button" disabled={busy} onClick={() => remove(h)}>Remover</button>
      </div>
      {open === h.id && (deliveries.length ? <div className="table-scroll"><table className="users-table"><thead><tr><th>Evento</th><th>Situação</th><th>Tentativas</th><th>Criada</th><th>Detalhe</th></tr></thead><tbody>
        {deliveries.map(d => <tr key={d.id}><td>{eventLabel(d.event)}</td><td>{DELIVERY_LABELS[d.status]}</td><td>{d.attempts}</td><td>{when(d.createdAt)}</td>
          <td>{d.status === "delivered" ? `HTTP ${d.responseStatus}` : d.lastError ?? "—"}{d.status === "pending" && d.attempts > 0 && <><br/><small className="hint">Nova tentativa {when(d.nextAttemptAt)}</small></>}</td></tr>)}
      </tbody></table></div> : <p className="hint">Nenhuma entrega nos últimos 30 dias.</p>)}
    </section>)}

    {canManageTokens && <section className="account-card">
      <h2>Tokens de API da organização</h2>
      <p>Cada pessoa cria os próprios tokens em <Link href="/conta">Minha conta</Link>. Aqui você vê todos e pode revogar qualquer um.</p>
      {tokens.length === 0 ? <p className="hint">Nenhum token criado.</p> : <div className="table-scroll"><table className="users-table"><thead><tr><th>Token</th><th>Pessoa</th><th>Papel</th><th>Último uso</th><th>Vence</th><th/></tr></thead><tbody>
        {tokens.map(t => { const active = !t.revokedAt && new Date(t.expiresAt) > new Date(); return <tr key={t.id}>
          <td>{t.name}<br/><small className="hint"><code>{t.prefix}…</code></small></td><td>{t.user.name}</td><td>{ROLE_LABELS[t.role]}</td>
          <td>{t.lastUsedAt ? when(t.lastUsedAt) : "Nunca"}</td><td>{when(t.expiresAt)}</td>
          <td>{active ? <button className="run-button" disabled={busy} onClick={() => revokeToken(t)}>Revogar</button> : t.revokedAt ? "Revogado" : "Vencido"}</td>
        </tr>; })}
      </tbody></table></div>}
    </section>}
  </main>;
}
