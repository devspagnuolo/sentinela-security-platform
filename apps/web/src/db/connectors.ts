import { and, asc, eq, isNull, lt, lte, or, sql } from "drizzle-orm";
import { CLOUD_PROVIDERS, CloudError, credentialHint, discoverHosts, type CloudCredentials, type CloudHttp, type CloudProvider } from "@/lib/cloud";
import { decrypt, encrypt } from "@/lib/crypto";
import { logger } from "@/lib/logger";
import { evaluateScope } from "@/lib/scope";
import type { Database } from "./client";
import { notify } from "./notifications";
import { assets, authorizations, cloudConnectors, discoveredHosts } from "./schema";
import { emitEvent } from "./webhooks";

/**
 * Conectores de nuvem e hostnames descobertos. A descoberta só informa: um
 * hostname encontrado só pode ser avaliado depois de cadastrado como ativo sob
 * um escopo aprovado, como qualquer outro.
 */
export const SYNC_INTERVAL_MS = 24 * 60 * 60_000;
const SYNC_STALE_MS = 10 * 60_000;
export const MAX_CONNECTORS = 10;

export type CloudConnector = {
  id: string; provider: CloudProvider; providerLabel: string; name: string; credentialHint: string; enabled: boolean;
  lastSyncAt: string | null; lastError: string | null; zoneCount: number | null; hostCount: number | null; nextSyncAt: string; createdAt: string;
};
/** asset: já é ativo · in_scope: coberto por escopo vigente · out_of_scope: nenhum escopo vigente cobre · internal: só aponta para IP privado. */
export type DiscoveryStatus = "asset" | "in_scope" | "out_of_scope" | "internal";
export type DiscoveredHost = {
  id: string; hostname: string; zone: string; recordTypes: string[]; targets: string[]; internal: boolean; current: boolean;
  firstSeenAt: string; lastSeenAt: string; connector: { id: string; name: string; provider: CloudProvider };
  status: DiscoveryStatus; assetId: string | null; authorization: { id: string; reference: string } | null;
};

type ConnectorRow = typeof cloudConnectors.$inferSelect;
const iso = (d: Date | null) => d?.toISOString() ?? null;
const toConnector = (r: ConnectorRow): CloudConnector => ({
  id: r.id, provider: r.provider as CloudProvider, providerLabel: CLOUD_PROVIDERS[r.provider as CloudProvider] ?? r.provider, name: r.name, credentialHint: r.credentialHint,
  enabled: r.enabled, lastSyncAt: iso(r.lastSyncAt), lastError: r.lastError, zoneCount: r.zoneCount, hostCount: r.hostCount, nextSyncAt: r.nextSyncAt.toISOString(), createdAt: r.createdAt.toISOString()
});
const hostOf = (url: string) => { try { return new URL(url).hostname.toLowerCase(); } catch { return ""; } };

/** Classifica hostnames contra os ativos e os escopos vigentes da organização. */
async function classifier(db: Database, organizationId: string, now: Date) {
  const [assetRows, scopes] = await Promise.all([
    db.select({ id: assets.id, url: assets.url }).from(assets).where(eq(assets.organizationId, organizationId)),
    db.select().from(authorizations).where(and(eq(authorizations.organizationId, organizationId), eq(authorizations.status, "approved")))
  ]);
  const byHost = new Map(assetRows.map(a => [hostOf(a.url), a.id]));
  return (hostname: string, internal: boolean) => {
    const assetId = byHost.get(hostname) ?? null;
    const scope = scopes.find(s => evaluateScope(s, hostname, now).ok);
    const status: DiscoveryStatus = assetId ? "asset" : internal ? "internal" : scope ? "in_scope" : "out_of_scope";
    return { status, assetId, authorization: scope ? { id: scope.id, reference: scope.reference } : null };
  };
}

export function connectorRepository(db: Database, organizationId: string, actorUserId: string | null = null) {
  const own = eq(cloudConnectors.organizationId, organizationId);
  const byId = (id: string) => and(own, eq(cloudConnectors.id, id));
  return {
    async list(): Promise<CloudConnector[]> {
      return (await db.select().from(cloudConnectors).where(own).orderBy(asc(cloudConnectors.name))).map(toConnector);
    },

    async row(id: string) {
      const [row] = await db.select().from(cloudConnectors).where(byId(id));
      return row;
    },

    async create(input: { name: string; credentials: CloudCredentials }, now = new Date()) {
      const [row] = await db.insert(cloudConnectors).values({
        organizationId, provider: input.credentials.provider, name: input.name, credentials: encrypt(JSON.stringify(input.credentials)),
        credentialHint: credentialHint(input.credentials), nextSyncAt: now, createdBy: actorUserId, createdAt: now
      }).returning();
      return row;
    },

    async update(id: string, changes: { name?: string; enabled?: boolean; credentials?: CloudCredentials }) {
      const [row] = await db.update(cloudConnectors).set({
        ...(changes.name && { name: changes.name }), ...(changes.enabled !== undefined && { enabled: changes.enabled }),
        ...(changes.credentials && { credentials: encrypt(JSON.stringify(changes.credentials)), credentialHint: credentialHint(changes.credentials), lastError: null, nextSyncAt: new Date() })
      }).where(byId(id)).returning();
      return row && toConnector(row);
    },

    async remove(id: string) {
      const [row] = await db.delete(cloudConnectors).where(byId(id)).returning({ id: cloudConnectors.id, name: cloudConnectors.name, provider: cloudConnectors.provider });
      return row;
    },

    /** Hostnames descobertos (por padrão só os vistos na última sincronização), já classificados. */
    async listHosts(filter: { includeStale?: boolean } = {}, now = new Date()): Promise<DiscoveredHost[]> {
      const conditions = [eq(discoveredHosts.organizationId, organizationId)];
      if (!filter.includeStale) conditions.push(eq(discoveredHosts.current, true));
      const rows = await db.select({ h: discoveredHosts, connector: { id: cloudConnectors.id, name: cloudConnectors.name, provider: cloudConnectors.provider } })
        .from(discoveredHosts).innerJoin(cloudConnectors, eq(cloudConnectors.id, discoveredHosts.connectorId))
        .where(and(...conditions)).orderBy(asc(discoveredHosts.hostname)).limit(10_000);
      const classify = await classifier(db, organizationId, now);
      return rows.map(({ h, connector }) => ({
        id: h.id, hostname: h.hostname, zone: h.zone, recordTypes: h.recordTypes, targets: h.targets, internal: h.internal, current: h.current,
        firstSeenAt: h.firstSeenAt.toISOString(), lastSeenAt: h.lastSeenAt.toISOString(), connector: { ...connector, provider: connector.provider as CloudProvider },
        ...classify(h.hostname, h.internal)
      }));
    }
  };
}

export type SyncResult = { ok: true; zones: number; hosts: number; newHosts: number; newOutOfScope: string[] } | { ok: false; error: string };

/** Sincroniza um conector: lê as zonas no provedor e atualiza os hostnames. Avisa a gestão sobre hostnames novos fora de escopo. */
export async function syncConnector(db: Database, connector: ConnectorRow, deps: { http?: CloudHttp; now?: Date } = {}): Promise<SyncResult> {
  const now = deps.now ?? new Date();
  const finish = (changes: Partial<typeof cloudConnectors.$inferInsert>) =>
    db.update(cloudConnectors).set({ syncLockedAt: null, nextSyncAt: new Date(now.getTime() + SYNC_INTERVAL_MS), ...changes }).where(eq(cloudConnectors.id, connector.id));
  let found;
  try {
    found = await discoverHosts(JSON.parse(decrypt(connector.credentials)) as CloudCredentials, { http: deps.http, now: () => now });
  } catch (error) {
    const message = (error instanceof CloudError ? error.message : "Erro interno ao sincronizar.").slice(0, 300);
    if (!(error instanceof CloudError)) logger.error("connector.sync_error", { connectorId: connector.id, error });
    await finish({ lastError: message, lastSyncAt: now });
    // Avisa só na primeira falha seguida, para não repetir o aviso a cada dia.
    if (!connector.lastError) await notify(db, connector.organizationId, { audience: "managers" }, {
      kind: "connector.failed", link: "/integracoes", title: `Conector ${connector.name} não sincronizou`, body: message
    });
    return { ok: false, error: message };
  }

  const known = new Set((await db.select({ hostname: discoveredHosts.hostname }).from(discoveredHosts).where(eq(discoveredHosts.connectorId, connector.id))).map(r => r.hostname));
  await db.transaction(async tx => {
    await tx.update(discoveredHosts).set({ current: false }).where(eq(discoveredHosts.connectorId, connector.id));
    for (let i = 0; i < found.hosts.length; i += 500) {
      await tx.insert(discoveredHosts).values(found.hosts.slice(i, i + 500).map(h => ({ organizationId: connector.organizationId, connectorId: connector.id, ...h, current: true, firstSeenAt: now, lastSeenAt: now })))
        .onConflictDoUpdate({ target: [discoveredHosts.connectorId, discoveredHosts.hostname], set: {
          zone: sql`excluded.zone`, recordTypes: sql`excluded.record_types`, targets: sql`excluded.targets`, internal: sql`excluded.internal`, current: true, lastSeenAt: now
        } });
    }
  });
  await finish({ lastError: null, lastSyncAt: now, zoneCount: found.zones, hostCount: found.hosts.length });

  const fresh = found.hosts.filter(h => !known.has(h.hostname));
  const classify = await classifier(db, connector.organizationId, now);
  const newOutOfScope = fresh.filter(h => classify(h.hostname, h.internal).status === "out_of_scope").map(h => h.hostname);
  if (newOutOfScope.length) {
    await notify(db, connector.organizationId, { audience: "managers" }, {
      kind: "discovery.out_of_scope", link: "/descoberta",
      title: `${newOutOfScope.length} hostname(s) novo(s) fora de escopo em ${connector.name}`,
      body: `${newOutOfScope.slice(0, 5).join(", ")}${newOutOfScope.length > 5 ? "…" : ""}. Confirme com o cliente se fazem parte do contrato antes de avaliar.`
    });
  }
  if (fresh.length) await emitEvent(db, connector.organizationId, "discovery.hosts_found", {
    connector: { id: connector.id, name: connector.name, provider: connector.provider },
    hosts: fresh.slice(0, 100).map(h => ({ hostname: h.hostname, zone: h.zone, status: classify(h.hostname, h.internal).status })),
    total: fresh.length, outOfScope: newOutOfScope.length
  }, now);
  return { ok: true, zones: found.zones, hosts: found.hosts.length, newHosts: fresh.length, newOutOfScope };
}

/** Pega o próximo conector vencido (atômico entre instâncias), já marcando a próxima sincronização. */
export async function claimDueConnector(db: Database, now = new Date()): Promise<ConnectorRow | undefined> {
  const next = db.select({ id: cloudConnectors.id }).from(cloudConnectors)
    .where(and(eq(cloudConnectors.enabled, true), lte(cloudConnectors.nextSyncAt, now), or(isNull(cloudConnectors.syncLockedAt), lt(cloudConnectors.syncLockedAt, new Date(now.getTime() - SYNC_STALE_MS)))))
    .orderBy(asc(cloudConnectors.nextSyncAt)).limit(1).for("update", { skipLocked: true });
  const [row] = await db.update(cloudConnectors).set({ syncLockedAt: now }).where(eq(cloudConnectors.id, sql`(${next})`)).returning();
  return row;
}

/** Sincroniza os conectores vencidos (worker). */
export async function syncDueConnectors(db: Database, deps: { http?: CloudHttp; now?: Date } = {}) {
  let synced = 0;
  for (let row = await claimDueConnector(db, deps.now); row; row = await claimDueConnector(db, deps.now)) {
    const result = await syncConnector(db, row, deps);
    if (!result.ok) logger.warn("connector.sync_failed", { connectorId: row.id, error: result.error });
    synced++;
  }
  return synced;
}
