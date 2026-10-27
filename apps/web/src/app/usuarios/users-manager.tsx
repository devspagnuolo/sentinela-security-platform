"use client";
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowLeft, Plus } from "lucide-react";
import { ROLE_LABELS, type Role } from "@/lib/auth/rbac";
import type { Member } from "@/db/users";

export default function UsersManager({ currentUserId, assignableRoles }: { currentUserId: string; assignableRoles: Role[] }) {
  const router = useRouter();
  const [members, setMembers] = useState<Member[]>([]), [notice, setNotice] = useState("");
  const [form, setForm] = useState({ name: "", email: "", role: assignableRoles.at(-1) ?? "viewer", password: "" });
  const load = useCallback(async () => {
    const r = await fetch("/api/users");
    if (r.status === 401) { router.replace("/login"); return []; }
    return r.ok ? (await r.json() as Member[]) : [];
  }, [router]);
  const refresh = async () => setMembers(await load());
  useEffect(() => { let active = true; load().then(m => { if (active) setMembers(m); }); return () => { active = false; }; }, [load]);
  async function send(url: string, method: string, body: unknown, ok: string) {
    const r = await fetch(url, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    setNotice(r.ok ? ok : (await r.json()).error ?? "Falha na operação.");
    if (r.ok) await refresh();
    return r.ok;
  }
  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (await send("/api/users", "POST", form, "Usuário criado. Compartilhe a senha inicial por um canal seguro.")) setForm({ ...form, name: "", email: "", password: "" });
  }
  const manageable = (m: Member) => m.id !== currentUserId && assignableRoles.includes(m.role);
  return <main className="content users-page">
    <Link className="button button-secondary" href="/"><ArrowLeft size={15}/>Voltar ao painel</Link>
    <h1>Usuários</h1>
    {notice && <div className="notice"><span>{notice}</span></div>}
    {assignableRoles.length > 0 && <form className="user-form" onSubmit={create}>
      <input placeholder="Nome" required value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
      <input placeholder="E-mail" type="email" required value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} />
      <select value={form.role} onChange={e => setForm({ ...form, role: e.target.value as Role })}>{assignableRoles.map(r => <option key={r} value={r}>{ROLE_LABELS[r]}</option>)}</select>
      <input placeholder="Senha inicial (12+ caracteres)" type="password" autoComplete="new-password" required minLength={12} value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} />
      <button className="button button-primary"><Plus size={15}/>Criar</button>
    </form>}
    <table className="users-table"><thead><tr><th>Nome</th><th>E-mail</th><th>Papel</th><th>Último acesso</th><th>2 etapas</th><th>Status</th></tr></thead><tbody>
      {members.map(m => <tr key={m.id}>
        <td>{m.name}{m.id === currentUserId && " (você)"}</td><td>{m.email}</td>
        <td>{manageable(m) ? <select value={m.role} onChange={e => void send(`/api/users/${m.id}`, "PATCH", { role: e.target.value }, "Papel atualizado.")}>{assignableRoles.map(r => <option key={r} value={r}>{ROLE_LABELS[r]}</option>)}</select> : ROLE_LABELS[m.role]}</td>
        <td>{m.lastLoginAt ? new Date(m.lastLoginAt).toLocaleString("pt-BR") : "Nunca"}</td>
        <td>{m.mfaEnabled ? "Ativa" : "Não configurada"}{manageable(m) && m.mfaEnabled && <> <button className="run-button" onClick={() => { if (confirm(`Resetar a verificação em duas etapas de ${m.name}? A pessoa precisará configurá-la de novo e as sessões dela serão encerradas.`)) void send(`/api/users/${m.id}`, "PATCH", { resetMfa: true }, "Verificação em duas etapas resetada e sessões encerradas."); }}>Resetar</button></>}</td>
        <td>{manageable(m) ? <button className="run-button" onClick={() => void send(`/api/users/${m.id}`, "PATCH", { disabled: !m.disabled }, m.disabled ? "Usuário reativado." : "Usuário desativado e sessões encerradas.")}>{m.disabled ? "Reativar" : "Desativar"}</button> : m.disabled ? "Desativado" : "Ativo"}</td>
      </tr>)}
    </tbody></table>
  </main>;
}
