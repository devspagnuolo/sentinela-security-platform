"use client";
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { ASSESSMENT_STATUS_LABELS } from "@/lib/labels";
import type { Assessment } from "@/lib/types";

const dateTime = (iso: string | null) => iso ? new Date(iso).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo", dateStyle: "short", timeStyle: "short" }) : "—";
const duration = (a: Assessment) => a.startedAt && a.finishedAt ? `${Math.max(1, Math.round((new Date(a.finishedAt).getTime() - new Date(a.startedAt).getTime()) / 1000))} s` : "—";

export default function AssessmentHistory() {
  const router = useRouter();
  const [runs, setRuns] = useState<Assessment[]>([]);
  const load = useCallback(async () => {
    const r = await fetch("/api/assessments?limit=200");
    if (r.status === 401) { router.replace("/login"); return null; }
    return r.ok ? await r.json() as Assessment[] : [];
  }, [router]);
  const pending = runs.some(r => r.status === "queued" || r.status === "running");
  useEffect(() => {
    let active = true;
    const refresh = () => load().then(r => { if (active && r) setRuns(r); });
    void refresh();
    // Enquanto há execução na fila ou em andamento, atualiza a cada poucos segundos.
    const timer = pending ? setInterval(refresh, 3000) : undefined;
    return () => { active = false; clearInterval(timer); };
  }, [load, pending]);

  return <main className="content users-page findings-page">
    <Link className="button button-secondary" href="/"><ArrowLeft size={15}/>Voltar ao painel</Link>
    <h1>Histórico de análises</h1>
    <p className="muted">Cada avaliação entra numa fila e roda em segundo plano. O escopo é conferido de novo na hora da execução; falhas de rede são repetidas até 3 vezes.</p>
    <div className="table-scroll">
      <table className="users-table"><thead><tr><th>Ativo</th><th>Situação</th><th>Origem</th><th>Pedida em</th><th>Duração</th><th>Resultado</th></tr></thead><tbody>
        {runs.map(r => <tr key={r.id}>
          <td><b>{r.assetName ?? "Ativo"}</b></td>
          <td><span className={`status-badge run-${r.status}`}>{ASSESSMENT_STATUS_LABELS[r.status]}</span>{r.attempts > 1 && <><br/><small className="muted">{r.attempts} tentativas</small></>}</td>
          <td>{r.trigger === "scheduled" ? "Agendada" : r.requestedBy?.name ?? "—"}</td>
          <td className="nowrap">{dateTime(r.createdAt)}</td>
          <td>{duration(r)}</td>
          <td>{r.status === "completed" && r.summary
            ? <small>{r.summary.observed} observado(s) · {r.summary.created} novo(s) · {r.summary.reopened} reaberto(s) · {r.summary.resolved} corrigido(s)</small>
            : r.error ? <small className="muted">{r.error}</small> : "—"}</td>
        </tr>)}
        {runs.length === 0 && <tr><td colSpan={6} className="muted">Nenhuma avaliação executada ainda.</td></tr>}
      </tbody></table>
    </div>
  </main>;
}
