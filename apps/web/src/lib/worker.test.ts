import { beforeAll, describe, expect, it, vi } from "vitest";
import { eq } from "drizzle-orm";
import { createDatabase, type Database } from "@/db/client";
import { notificationRepository } from "@/db/notifications";
import { tenantRepository } from "@/db/repository";
import { assessments, authorizations, findings, organizations } from "@/db/schema";
import { memberRepository } from "@/db/users";
import type { Role } from "./auth/rbac";
import { TransientAssessmentError } from "./scanner";
import { claimNext, drainQueue, housekeeping, MAX_ATTEMPTS, processRun, recoverStale, RETRY_BASE_MS, scheduleDue, STALE_AFTER_MS } from "./worker";

const DAY = 86_400_000;
const M = "TEST-METHOD";
let db: Database;
let n = 0;

const observation = (title = "HSTS ausente", severity: "low" | "high" = "low") => ({ title, severity, category: "HTTP Headers", description: "d", evidence: "e", recommendation: "r", references: [] });

/** Organização com membros dos papéis pedidos, um escopo aprovado (*.example.com) e um ativo. */
async function setup(roles: Role[] = ["owner", "analyst", "viewer"], validDays = 30) {
  const [org] = await db.insert(organizations).values({ slug: `w-${++n}`, name: `W ${n}` }).returning();
  const members = Object.fromEntries(await Promise.all(roles.map(async role => [role, await memberRepository(db, org.id).create({ email: `${role}-${n}@w.example`, name: `${role} ${n}`, role, password: "correct-horse-battery-staple" })])));
  const [scope] = await db.insert(authorizations).values({ organizationId: org.id, reference: `AUT-${n}`, hostnames: ["*.example.com"], status: "approved", validUntil: new Date(Date.now() + validDays * DAY) }).returning();
  const repo = tenantRepository(db, org.id, members.analyst?.id ?? null);
  const asset = await repo.createAsset({ name: `app-${n}`, url: `https://app${n}.example.com`, kind: "Web application", owner: "TI", authorizationId: scope.id });
  return { orgId: org.id, members, scope, asset, repo };
}
const inbox = (orgId: string, userId: string) => notificationRepository(db, orgId, userId);

beforeAll(async () => {
  db = await createDatabase({ NODE_ENV: "test", SENTINELA_SEED_DEMO: "0" });
});

describe("fila de avaliações", () => {
  it("um job pendente por ativo; o worker executa, consolida e avisa a operação sobre achado alto", async () => {
    const { orgId, members, asset, repo } = await setup();
    const first = await repo.queueAssessment(asset.id, { method: M });
    const again = await repo.queueAssessment(asset.id, { method: M });
    expect(first.queued).toBe(true);
    expect(again).toMatchObject({ queued: false, assessment: { id: first.assessment.id } });
    expect((await repo.getAsset(asset.id))?.lastAssessment).toMatchObject({ status: "queued" });

    const assess = vi.fn(async () => [observation("CSP ausente", "high"), observation()]);
    expect(await drainQueue(db, { assess })).toBe(1);
    expect(assess).toHaveBeenCalledOnce();
    const done = await repo.getAssessment(first.assessment.id);
    expect(done).toMatchObject({ status: "completed", attempts: 1, summary: { observed: 2, created: 2, reopened: 0, resolved: 0 } });
    expect(done?.findingIds).toHaveLength(2);

    // Achado alto novo: Owner e Analista são avisados; Leitor não.
    expect((await inbox(orgId, members.analyst.id).list())[0]).toMatchObject({ kind: "assessment.attention", link: "/achados" });
    expect(await inbox(orgId, members.owner.id).unreadCount()).toBe(1);
    expect(await inbox(orgId, members.viewer.id).unreadCount()).toBe(0);

    // Depois de concluída, uma nova avaliação pode ser enfileirada.
    expect((await repo.queueAssessment(asset.id, { method: M })).queued).toBe(true);
    await drainQueue(db, { assess: async () => [observation("CSP ausente", "high"), observation()] });
    expect(await inbox(orgId, members.analyst.id).unreadCount()).toBe(1);
  });

  it("confere o escopo na execução: revogado depois de enfileirar, falha sem chamar o scanner", async () => {
    const { orgId, members, scope, asset, repo } = await setup();
    const { assessment } = await repo.queueAssessment(asset.id, { method: M });
    await db.update(authorizations).set({ status: "revoked", revokedAt: new Date() }).where(eq(authorizations.id, scope.id));
    const assess = vi.fn();
    await drainQueue(db, { assess });
    expect(assess).not.toHaveBeenCalled();
    expect(await repo.getAssessment(assessment.id)).toMatchObject({ status: "failed", error: expect.stringContaining("revogada") });
    expect((await repo.listAudit(5)).map(e => e.action)).toContain("assessment.blocked");
    // Quem pediu é avisado.
    expect((await inbox(orgId, members.analyst.id).list())[0]).toMatchObject({ kind: "assessment.failed" });
    expect(await inbox(orgId, members.owner.id).unreadCount()).toBe(0);
  });

  it("falha de rede tenta de novo com espera crescente; erro definitivo falha de imediato", async () => {
    const { asset, repo } = await setup();
    const { assessment } = await repo.queueAssessment(asset.id, { method: M });
    const flaky = vi.fn(async () => { throw new TransientAssessmentError("Tempo limite excedido ao contatar o alvo."); });
    let now = new Date();
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      const run = await claimNext(db, now);
      expect(run).toMatchObject({ id: assessment.id, attempts: attempt });
      await processRun(db, run!, { assess: flaky, now: () => now });
      const [row] = await db.select().from(assessments).where(eq(assessments.id, assessment.id));
      if (attempt < MAX_ATTEMPTS) {
        expect(row).toMatchObject({ status: "queued", error: "Tempo limite excedido ao contatar o alvo." });
        expect(row.runAfter.getTime()).toBe(now.getTime() + RETRY_BASE_MS * 2 ** (attempt - 1));
        expect(await claimNext(db, now)).toBeUndefined(); // ainda não venceu a espera
        now = row.runAfter;
      } else expect(row).toMatchObject({ status: "failed", attempts: MAX_ATTEMPTS });
    }

    const other = await repo.queueAssessment(asset.id, { method: M });
    const permanent = vi.fn(async () => { throw new Error("O hostname não consta na lista de alvos autorizados pelo operador."); });
    await drainQueue(db, { assess: permanent });
    expect(permanent).toHaveBeenCalledOnce();
    expect(await repo.getAssessment(other.assessment.id)).toMatchObject({ status: "failed", attempts: 1, error: expect.stringContaining("lista de alvos") });
  });

  it("job travado em running volta para a fila e, depois do limite, falha", async () => {
    const { asset, repo } = await setup();
    const { assessment } = await repo.queueAssessment(asset.id, { method: M });
    const t0 = new Date();
    await claimNext(db, t0);
    expect(await recoverStale(db, new Date(t0.getTime() + 60_000))).toBe(0);
    const later = new Date(t0.getTime() + STALE_AFTER_MS + 1);
    await recoverStale(db, later);
    expect(await repo.getAssessment(assessment.id)).toMatchObject({ status: "queued" });
    await db.update(assessments).set({ status: "running", attempts: MAX_ATTEMPTS, lockedAt: t0 }).where(eq(assessments.id, assessment.id));
    await recoverStale(db, later);
    expect(await repo.getAssessment(assessment.id)).toMatchObject({ status: "failed", error: "Execução interrompida repetidamente." });
  });

  it("dois workers nunca pegam o mesmo job", async () => {
    const a = await setup(["analyst"]);
    const b = await setup(["analyst"]);
    await a.repo.queueAssessment(a.asset.id, { method: M });
    await b.repo.queueAssessment(b.asset.id, { method: M });
    // Cada chamada marca exatamente um job como running.
    const one = await claimNext(db);
    expect((await db.select().from(assessments).where(eq(assessments.status, "running"))).map(r => r.id)).toEqual([one!.id]);
    await db.update(assessments).set({ status: "queued", lockedAt: null }).where(eq(assessments.id, one!.id));
    const claimed = (await Promise.all([claimNext(db), claimNext(db), claimNext(db)])).filter(Boolean).map(r => r!.id);
    expect(new Set(claimed).size).toBe(claimed.length);
    expect(claimed.length).toBeGreaterThanOrEqual(2);
    await drainQueue(db, { assess: async () => [] });
  });
});

describe("reavaliação agendada", () => {
  it("enfileira quando vence, avança a próxima data e não duplica", async () => {
    const { asset, repo } = await setup(["analyst"]);
    const now = new Date();
    const scheduled = await repo.setSchedule(asset.id, 7, now);
    expect(scheduled).toMatchObject({ scheduleIntervalDays: 7, nextAssessmentAt: new Date(now.getTime() + 7 * DAY).toISOString() });
    expect(await scheduleDue(db, now)).toBe(0);

    const due = new Date(now.getTime() + 7 * DAY + 1000);
    expect(await scheduleDue(db, due)).toBe(1);
    expect(await scheduleDue(db, due)).toBe(0);
    const [run] = await repo.listAssessments({ assetId: asset.id });
    expect(run).toMatchObject({ status: "queued", trigger: "scheduled", requestedBy: null });
    expect((await repo.getAsset(asset.id))?.nextAssessmentAt).toBe(new Date(due.getTime() + 7 * DAY).toISOString());
    await drainQueue(db, { assess: async () => [] });

    await repo.setSchedule(asset.id, null, now);
    expect(await repo.getAsset(asset.id)).toMatchObject({ scheduleIntervalDays: null, nextAssessmentAt: null });
    expect((await repo.listAudit(1))[0]).toMatchObject({ action: "asset.schedule_updated", metadata: { intervalDays: null, previous: 7 } });
  });
});

describe("tarefas periódicas e avisos", () => {
  it("avisa a gestão uma vez sobre escopo perto do vencimento e sobre aceite de risco vencido", async () => {
    const { orgId, members, asset, repo } = await setup(["owner", "analyst"], 10);
    const { findings: [f] } = await repo.recordAssessment(asset.id, M, new Date(), [observation()]);
    await db.update(findings).set({ status: "accepted", acceptedUntil: new Date(Date.now() - 1000) }).where(eq(findings.id, f.id));

    await housekeeping(db);
    await housekeeping(db);
    const ownerInbox = await inbox(orgId, members.owner.id).list();
    expect(ownerInbox.filter(x => x.kind === "scope.expiring")).toHaveLength(1);
    expect(ownerInbox.find(x => x.kind === "scope.expiring")?.title).toMatch(/vence em (9|10) dia/);
    expect(ownerInbox.filter(x => x.kind === "finding.acceptance_expired")).toHaveLength(1);
    expect((await repo.getFinding(f.id))?.status).toBe("open");
    expect(await inbox(orgId, members.analyst.id).unreadCount()).toBe(0);
  });

  it("escopo novo avisa quem aprova, menos quem cadastrou; cada um lê só os próprios avisos", async () => {
    const [org] = await db.insert(organizations).values({ slug: `w-${++n}`, name: "Avisos" }).returning();
    const users = memberRepository(db, org.id);
    const admin = await users.create({ email: `adm-${n}@w.example`, name: "Admin", role: "admin", password: "correct-horse-battery-staple" });
    const owner = await users.create({ email: `own-${n}@w.example`, name: "Owner", role: "owner", password: "correct-horse-battery-staple" });
    await tenantRepository(db, org.id, admin.id).createAuthorization({ reference: "CT-9", hostnames: ["x.example.com"], excludedHostnames: [], validFrom: null, validUntil: new Date(Date.now() + 30 * DAY) });
    expect(await inbox(org.id, admin.id).unreadCount()).toBe(0);
    const [item] = await inbox(org.id, owner.id).list();
    expect(item).toMatchObject({ kind: "scope.pending", title: "Escopo CT-9 aguarda aprovação", readAt: null });

    expect(await inbox(org.id, admin.id).markRead([item.id])).toBe(0);
    expect(await inbox(org.id, owner.id).markRead(["not-a-uuid"])).toBe(0);
    expect(await inbox(org.id, owner.id).markRead()).toBe(1);
    expect(await inbox(org.id, owner.id).unreadCount()).toBe(0);
  });
});
