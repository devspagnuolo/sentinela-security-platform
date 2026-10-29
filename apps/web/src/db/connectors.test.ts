import { eq } from "drizzle-orm";
import { beforeAll, describe, expect, it, vi } from "vitest";
import type { CloudHttp } from "@/lib/cloud";
import { createDatabase, type Database } from "./client";
import { claimDueConnector, connectorRepository, SYNC_INTERVAL_MS, syncConnector, syncDueConnectors } from "./connectors";
import { notificationRepository } from "./notifications";
import { tenantRepository } from "./repository";
import { authorizations, cloudConnectors, organizations } from "./schema";
import { memberRepository } from "./users";

let db: Database;
let n = 0;
const DAY = 86_400_000;
const zone = "b".repeat(32);

/** Cloudflare falsa: uma zona com os registros dados. */
function cloudflare(records: { name: string; type: string; content: string }[]): CloudHttp {
  return async url => {
    const path = new URL(url).pathname;
    const body = path.endsWith("/zones") ? { success: true, result: [{ id: zone, name: "cliente.com.br" }], result_info: { page: 1, total_pages: 1 } }
      : { success: true, result: records, result_info: { page: 1, total_pages: 1 } };
    return { status: 200, text: async () => JSON.stringify(body) };
  };
}

async function setup() {
  const [org] = await db.insert(organizations).values({ slug: `c-${++n}`, name: `C ${n}` }).returning();
  const owner = await memberRepository(db, org.id).create({ email: `owner-${n}@c.example`, name: "Owner", role: "owner", password: "correct-horse-battery-staple" });
  const [scope] = await db.insert(authorizations).values({ organizationId: org.id, reference: `AUT-${n}`, hostnames: ["*.cliente.com.br"], excludedHostnames: ["legado.cliente.com.br"], status: "approved", validUntil: new Date(Date.now() + 30 * DAY) }).returning();
  return { orgId: org.id, owner, scope, connectors: connectorRepository(db, org.id, owner.id) };
}

beforeAll(async () => {
  db = await createDatabase({ NODE_ENV: "test", SENTINELA_SEED_DEMO: "0" });
});

describe("conectores de nuvem", () => {
  it("sincroniza, classifica contra ativos e escopos e avisa sobre hostnames novos fora de escopo", async () => {
    const { orgId, owner, scope, connectors } = await setup();
    await tenantRepository(db, orgId).createAsset({ name: "Portal", url: "https://portal.cliente.com.br", kind: "Web application", owner: "TI", authorizationId: scope.id });
    const row = await connectors.create({ name: "Cloudflare do cliente", credentials: { provider: "cloudflare", apiToken: "t".repeat(40) } });
    expect(row.credentials).not.toContain("tttt");
    const records = [
      { name: "portal.cliente.com.br", type: "A", content: "93.184.216.34" },
      { name: "api.cliente.com.br", type: "CNAME", content: "lb.provedor.net" },
      { name: "legado.cliente.com.br", type: "A", content: "93.184.216.35" },
      { name: "cliente.com.br", type: "A", content: "93.184.216.36" },
      { name: "vpn.cliente.com.br", type: "A", content: "10.1.2.3" }
    ];
    const result = await syncConnector(db, row, { http: cloudflare(records) });
    expect(result).toMatchObject({ ok: true, zones: 1, hosts: 5, newHosts: 5, newOutOfScope: ["cliente.com.br", "legado.cliente.com.br"] });
    const hosts = Object.fromEntries((await connectors.listHosts()).map(h => [h.hostname, h.status]));
    expect(hosts).toEqual({ "api.cliente.com.br": "in_scope", "cliente.com.br": "out_of_scope", "legado.cliente.com.br": "out_of_scope", "portal.cliente.com.br": "asset", "vpn.cliente.com.br": "internal" });
    const [notice] = await notificationRepository(db, orgId, owner.id).list();
    expect(notice).toMatchObject({ kind: "discovery.out_of_scope", link: "/descoberta" });

    // Na próxima sincronização, o que sumiu deixa de ser atual e não há novo aviso.
    const again = await syncConnector(db, (await connectors.row(row.id))!, { http: cloudflare(records.slice(0, 2)) });
    expect(again).toMatchObject({ ok: true, newHosts: 0, newOutOfScope: [] });
    expect((await connectors.listHosts()).map(h => h.hostname)).toEqual(["api.cliente.com.br", "portal.cliente.com.br"]);
    expect(await connectors.listHosts({ includeStale: true })).toHaveLength(5);
    expect(await notificationRepository(db, orgId, owner.id).unreadCount()).toBe(1);
    // Outra organização não enxerga nada.
    expect(await connectorRepository(db, (await setup()).orgId).listHosts()).toEqual([]);
  });

  it("falha registra o erro, avisa uma vez e mantém os hostnames anteriores", async () => {
    const { orgId, owner, connectors } = await setup();
    const row = await connectors.create({ name: "AWS", credentials: { provider: "aws_route53", accessKeyId: "AKIAABCDEFGHIJKLMNOP", secretAccessKey: "s".repeat(40) } });
    const denied: CloudHttp = async () => ({ status: 403, text: async () => "<ErrorResponse><Error><Message>no</Message></Error></ErrorResponse>" });
    expect(await syncConnector(db, row, { http: denied })).toMatchObject({ ok: false, error: expect.stringContaining("recusou") });
    const failed = (await connectors.row(row.id))!;
    expect(failed.lastError).toContain("recusou");
    await syncConnector(db, failed, { http: denied });
    expect(await notificationRepository(db, orgId, owner.id).unreadCount()).toBe(1);
  });

  it("o worker sincroniza só os vencidos e ligados, um de cada vez", async () => {
    const { connectors } = await setup();
    const now = new Date(Date.now() + 365 * DAY);
    const due = await connectors.create({ name: "Vencido", credentials: { provider: "cloudflare", apiToken: "u".repeat(40) } });
    const off = await connectors.create({ name: "Desligado", credentials: { provider: "cloudflare", apiToken: "v".repeat(40) } });
    await connectors.update(off.id, { enabled: false });
    // Outros testes também deixam conectores vencidos; a Cloudflare falsa responde a todos.
    const http = vi.fn(cloudflare([{ name: "www.cliente.com.br", type: "A", content: "93.184.216.34" }]));
    expect(await syncDueConnectors(db, { http, now })).toBeGreaterThanOrEqual(1);
    const [synced] = await db.select().from(cloudConnectors).where(eq(cloudConnectors.id, due.id));
    expect(synced).toMatchObject({ hostCount: 1, syncLockedAt: null, nextSyncAt: new Date(now.getTime() + SYNC_INTERVAL_MS) });
    expect((await connectors.row(off.id))?.lastSyncAt).toBeNull();
    expect(await claimDueConnector(db, now)).toBeUndefined();
  });
});
