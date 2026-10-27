"use client";
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowLeft, CheckCheck } from "lucide-react";
import { timeAgo } from "@/lib/labels";
import type { Notification } from "@/lib/types";

export default function NotificationCenter() {
  const router = useRouter();
  const [items, setItems] = useState<Notification[]>([]), [unread, setUnread] = useState(0);
  const load = useCallback(async () => {
    const r = await fetch("/api/notifications?limit=100");
    if (r.status === 401) { router.replace("/login"); return null; }
    return r.ok ? await r.json() as { unread: number; items: Notification[] } : null;
  }, [router]);
  useEffect(() => { let active = true; load().then(r => { if (active && r) { setItems(r.items); setUnread(r.unread); } }); return () => { active = false; }; }, [load]);

  async function markRead(ids?: string[]) {
    const r = await fetch("/api/notifications/read", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(ids ? { ids } : {}) });
    if (!r.ok) return;
    const fresh = await load();
    if (fresh) { setItems(fresh.items); setUnread(fresh.unread); }
  }

  return <main className="content users-page findings-page">
    <Link className="button button-secondary" href="/"><ArrowLeft size={15}/>Voltar ao painel</Link>
    <div className="scope-head"><h1>Notificações</h1>{unread > 0 && <button className="button button-secondary" onClick={() => void markRead()}><CheckCheck size={15}/>Marcar todas como lidas</button>}</div>
    <p className="muted">Achados altos ou críticos novos, avaliações não concluídas, escopos aguardando aprovação ou perto do vencimento e aceites de risco vencidos. Avisos lidos são apagados após 90 dias.</p>
    <ul className="notification-list">
      {items.map(n => <li key={n.id} className={n.readAt ? undefined : "unread"}>
        <div>
          <b>{n.title}</b>
          {n.body && <p className="muted">{n.body}</p>}
          <small className="muted">{timeAgo(n.createdAt)}</small>
        </div>
        <div className="row-actions">
          {n.link && <Link className="run-button" href={n.link} onClick={() => { if (!n.readAt) void markRead([n.id]); }}>Abrir</Link>}
          {!n.readAt && <button className="run-button" onClick={() => void markRead([n.id])}>Marcar como lida</button>}
        </div>
      </li>)}
      {items.length === 0 && <li className="muted">Nenhuma notificação.</li>}
    </ul>
  </main>;
}
