import { beforeAll, describe, expect, it } from "vitest";
import { createDatabase, type Database } from "./client";
import { tenantRepository } from "./repository";
import { authorizations, organizations } from "./schema";
import { seedDemo } from "./seed";

let db: Database;
let orgA: string;
let orgB: string;
let scopeA: string;

const DAY = 24 * 60 * 60 * 1000;
const asset = (host: string) => ({ name: host, url: `https://${host}`, kind: "API" as const, owner: "TI", authorizationId: scopeA });
const finding = (title = "HSTS ausente", evidence = "e") => ({ title, severity: "low" as const, category: "HTTP Headers", description: "d", evidence, recommendation: "r", references: ["OWASP"] });

beforeAll(async () => {
  db = await createDatabase({ NODE_ENV: "test", SENTINELA_SEED_DEMO: "0" });
  [{ id: orgA }, { id: orgB }] = await db.insert(organizations).values([{ slug: "a", name: "A" }, { slug: "b", name: "B" }]).returning();
  [{ id: scopeA }] = await db.insert(authorizations).values({ organizationId: orgA, reference: "AUT-1", hostnames: ["*.example.com"], status: "approved", validUntil: new Date(Date.now() + 30 * DAY) }).returning();
});

describe("tenantRepository", () => {
  it("grava e lê ativos, execuções e achados da própria organização", async () => {
    const repo = tenantRepository(db, orgA);
    const created = await repo.createAsset(asset("a.example.com"));
    expect(created).toMatchObject({ authorizationRef: "AUT-1", scopeOk: true, scopeState: "active" });
    const { run, findings } = await repo.recordAssessment(created.id, "SENTINELA-HTTP-001", new Date(), [finding()]);
    expect(run.findingIds).toEqual([findings[0].id]);
    expect((await repo.latestCompletedAssessment(created.id))?.findings.map(f => f.id)).toEqual(run.findingIds);
    expect((await repo.listAssessments()).map(r => r.id)).toContain(run.id);
  });

  it("recusa ativo fora do escopo ou com autorização de outra organização", async () => {
    const repo = tenantRepository(db, orgA);
    await expect(repo.createAsset(asset("example.org"))).rejects.toThrow("não está entre os autorizados");
    await expect(tenantRepository(db, orgB).createAsset(asset("b.example.com"))).rejects.toThrow("não encontrada");
  });

  it("consolida achados entre avaliações, resolve os ausentes e reabre os que voltam", async () => {
    const repo = tenantRepository(db, orgA);
    const target = await repo.createAsset(asset("ciclo.example.com"));
    const first = await repo.recordAssessment(target.id, "M", new Date(), [finding("HSTS ausente", "e1"), finding("CSP ausente")]);
    const hsts = first.findings.find(f => f.title === "HSTS ausente")!;
    const csp = first.findings.find(f => f.title === "CSP ausente")!;

    // Mesmo problema não duplica; o que sumiu vira "corrigido".
    const second = await repo.recordAssessment(target.id, "M", new Date(), [finding("hsts AUSENTE", "e2")]);
    expect(second.findings.map(f => f.id)).toEqual([hsts.id]);
    expect((await repo.getFinding(csp.id))?.status).toBe("fixed");
    expect((await repo.listFindings({ assetId: target.id })).length).toBe(2);
    expect((await repo.latestCompletedAssessment(target.id))?.findings[0].evidence).toBe("e2");

    // Falso positivo continua falso positivo; corrigido que volta é reaberto.
    await repo.updateFindingStatus(hsts.id, { status: "false_positive", reason: "Header aplicado no CDN." });
    await repo.recordAssessment(target.id, "M", new Date(), [finding("HSTS ausente"), finding("CSP ausente")]);
    expect((await repo.getFinding(hsts.id))?.status).toBe("false_positive");
    expect((await repo.getFinding(csp.id))?.status).toBe("open");
    expect((await repo.listFindingEvents(csp.id)).map(e => [e.fromStatus, e.toStatus])).toEqual([["open", "fixed"], ["fixed", "open"]]);
  });

  it("aceite de risco vence e volta a aberto", async () => {
    const repo = tenantRepository(db, orgA);
    const target = await repo.createAsset(asset("aceite.example.com"));
    const { findings: [f] } = await repo.recordAssessment(target.id, "M", new Date(), [finding()]);
    await repo.updateFindingStatus(f.id, { status: "accepted", reason: "Mitigado por WAF.", acceptedUntil: new Date(Date.now() - 1000) });
    const [listed] = await repo.listFindings({ assetId: target.id });
    expect(listed).toMatchObject({ status: "open", statusReason: "Prazo do aceite de risco venceu.", acceptedUntil: null });
  });

  it("isola completamente os dados entre organizações", async () => {
    const a = tenantRepository(db, orgA);
    const b = tenantRepository(db, orgB);
    const secret = await a.createAsset(asset("secreto.example.com"));
    const { findings: [f] } = await a.recordAssessment(secret.id, "SENTINELA-HTTP-001", new Date(), [finding()]);

    expect(await b.getAsset(secret.id)).toBeUndefined();
    expect(await b.latestCompletedAssessment(secret.id)).toBeUndefined();
    expect((await b.listAssets()).map(x => x.id)).not.toContain(secret.id);
    expect(await b.listFindings()).toEqual([]);
    expect(await b.listAssessments()).toEqual([]);
    expect(await b.listAuthorizations()).toEqual([]);
    expect(await b.getFinding(f.id)).toBeUndefined();
    expect(await b.listFindingEvents(f.id)).toEqual([]);
    await expect(b.updateFindingStatus(f.id, { status: "fixed" })).rejects.toThrow("não encontrado");
    await expect(b.recordAssessment(secret.id, "SENTINELA-HTTP-001", new Date(), [finding()])).rejects.toThrow("Ativo não encontrado");
    expect((await b.listAudit()).every(e => e.targetId !== secret.id)).toBe(true);
  });

  it("trata ids malformados como inexistentes", async () => {
    const repo = tenantRepository(db, orgA);
    expect(await repo.getAsset("ast-001")).toBeUndefined();
    expect(await repo.getAuthorization("x")).toBeUndefined();
    expect(await repo.latestCompletedAssessment("'; drop table assets; --")).toBeUndefined();
  });

  it("audita cadastro e execução em ordem cronológica inversa", async () => {
    const repo = tenantRepository(db, orgA, null);
    const created = await repo.createAsset(asset("audit.example.com"));
    await repo.recordAssessment(created.id, "SENTINELA-HTTP-001", new Date(), []);
    const [last, previous] = await repo.listAudit(2);
    expect(last).toMatchObject({ action: "assessment.completed", targetId: created.id, metadata: { observed: 0 } });
    expect(previous).toMatchObject({ action: "asset.created", targetId: created.id });
  });
});

describe("seedDemo", () => {
  it("é idempotente e cria escopo vigente para os ativos", async () => {
    const first = await seedDemo(db);
    expect(await seedDemo(db)).toBe(first);
    const assets = await tenantRepository(db, first).listAssets();
    expect(assets).toHaveLength(2);
    expect(assets.every(a => a.scopeOk)).toBe(true);
  });
});
