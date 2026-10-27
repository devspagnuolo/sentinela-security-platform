import { beforeAll, describe, expect, it } from "vitest";
import { createDatabase, type Database } from "./client";
import { tenantRepository } from "./repository";
import { organizations } from "./schema";
import { seedDemo } from "./seed";

let db: Database;
let orgA: string;
let orgB: string;

const asset = (url: string) => ({ name: url, url, kind: "API" as const, owner: "TI", approved: true, authorizationRef: "AUT-1" });
const finding = { title: "HSTS ausente", severity: "low" as const, category: "HTTP Headers", description: "d", evidence: "e", recommendation: "r", references: ["OWASP"] };

beforeAll(async () => {
  db = await createDatabase({ NODE_ENV: "test", SENTINELA_SEED_DEMO: "0" });
  [{ id: orgA }, { id: orgB }] = await db.insert(organizations).values([{ slug: "a", name: "A" }, { slug: "b", name: "B" }]).returning();
});

describe("tenantRepository", () => {
  it("grava e lê ativos, execuções e achados da própria organização", async () => {
    const repo = tenantRepository(db, orgA);
    const created = await repo.createAsset(asset("https://a.example.com"));
    const { run, findings } = await repo.recordAssessment(created.id, "SENTINELA-HTTP-001", new Date(), [finding]);
    expect(run.findingIds).toEqual([findings[0].id]);
    expect((await repo.latestCompletedAssessment(created.id))?.findings.map(f => f.id)).toEqual(run.findingIds);
    expect((await repo.listAssessments()).map(r => r.id)).toContain(run.id);
  });

  it("isola completamente os dados entre organizações", async () => {
    const a = tenantRepository(db, orgA);
    const b = tenantRepository(db, orgB);
    const secret = await a.createAsset(asset("https://secreto.example.com"));
    await a.recordAssessment(secret.id, "SENTINELA-HTTP-001", new Date(), [finding]);

    expect(await b.getAsset(secret.id)).toBeUndefined();
    expect(await b.latestCompletedAssessment(secret.id)).toBeUndefined();
    expect((await b.listAssets()).map(x => x.id)).not.toContain(secret.id);
    expect(await b.listFindings()).toEqual([]);
    expect(await b.listAssessments()).toEqual([]);
    await expect(b.recordAssessment(secret.id, "SENTINELA-HTTP-001", new Date(), [finding])).rejects.toThrow("Ativo não encontrado");
    expect((await b.listAudit()).every(e => e.targetId !== secret.id)).toBe(true);
  });

  it("trata ids malformados como inexistentes", async () => {
    const repo = tenantRepository(db, orgA);
    expect(await repo.getAsset("ast-001")).toBeUndefined();
    expect(await repo.latestCompletedAssessment("'; drop table assets; --")).toBeUndefined();
  });

  it("audita cadastro e execução em ordem cronológica inversa", async () => {
    const repo = tenantRepository(db, orgA, null);
    const created = await repo.createAsset(asset("https://audit.example.com"));
    await repo.recordAssessment(created.id, "SENTINELA-HTTP-001", new Date(), []);
    const [last, previous] = await repo.listAudit(2);
    expect(last).toMatchObject({ action: "assessment.completed", targetId: created.id, metadata: { findings: 0 } });
    expect(previous).toMatchObject({ action: "asset.created", targetId: created.id });
  });
});

describe("seedDemo", () => {
  it("é idempotente", async () => {
    const first = await seedDemo(db);
    expect(await seedDemo(db)).toBe(first);
    expect(await tenantRepository(db, first).listAssets()).toHaveLength(2);
  });
});
