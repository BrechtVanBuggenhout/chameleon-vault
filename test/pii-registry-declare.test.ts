import { describe, expect, it, jest } from '@jest/globals';
import Fastify from 'fastify';
import { PiiRegistryService, type PiiDeclarationStore } from '../src/services/pii-registry-service.js';
import { buildManualEntry } from '../src/services/pii-registry-validation.js';
import { piiRegistryRoutes } from '../src/routes/pii-registry.js';
import type { PiiRegistryDeclarationInput, PiiRegistryEntry } from '../src/types/pii-registry.js';

const WRITE_TOKEN = 'test-write-token';

const validInput: PiiRegistryDeclarationInput = {
  resourceId: 'bigquery:acme.fivetran_hubspot.contacts',
  system: 'bigquery',
  resourceLayer: 'RAW',
  tenantIdColumn: 'tenant_id',
  userIdColumn: 'user_id',
  piiFields: [{ name: 'email', classification: 'DIRECT_IDENTIFIER', handling: 'ENCRYPT' }],
};

class FakeStore implements PiiDeclarationStore {
  public upserts: PiiRegistryEntry[] = [];
  public deletes: Array<{ tenantId: string; resourceId: string }> = [];
  public watermarks = new Map<string, string>();
  async upsert(entry: PiiRegistryEntry): Promise<void> {
    this.upserts.push(entry);
  }
  async delete(tenantId: string, resourceId: string): Promise<void> {
    this.deletes.push({ tenantId, resourceId });
  }
  async advanceSyncWatermark(tenantId: string, resourceId: string, candidateIso: string): Promise<string> {
    const key = `${tenantId}:${resourceId}`;
    const current = this.watermarks.get(key);
    if (!current || new Date(candidateIso).getTime() > new Date(current).getTime()) {
      this.watermarks.set(key, candidateIso);
      return candidateIso;
    }
    return current;
  }
}

describe('buildManualEntry (validation)', () => {
  it('assembles a manual entry from a valid declaration', () => {
    const { entry, errors } = buildManualEntry(validInput, 'acme');
    expect(errors).toEqual([]);
    expect(entry).toBeDefined();
    expect(entry?.ownerConnector).toBe('manual');
    expect(entry?.tenantId).toBe('acme');
    expect(entry?.status).toBe('PENDING_REVIEW');
    expect(entry?.piiFields[0].confidence).toBe('DECLARED');
  });

  it('carries updatedAtColumn through from the input to the built entry', () => {
    const { entry } = buildManualEntry({ ...validInput, updatedAtColumn: 'modified_at' }, 'acme');
    expect(entry?.updatedAtColumn).toBe('modified_at');
  });

  it('leaves updatedAtColumn undefined when not supplied', () => {
    const { entry } = buildManualEntry(validInput, 'acme');
    expect(entry?.updatedAtColumn).toBeUndefined();
  });

  it('collects errors for bad enums and empty fields', () => {
    const { entry, errors } = buildManualEntry(
      { resourceId: 'not-a-uri', system: 'mysql' as never, piiFields: [] },
      'acme'
    );
    expect(entry).toBeUndefined();
    expect(errors.length).toBeGreaterThanOrEqual(3);
  });

  it('requires a tenantId', () => {
    const { errors } = buildManualEntry(validInput, '');
    expect(errors.some((e) => e.includes('tenantId'))).toBe(true);
  });

  it('defaults sourceRedactionStrategy to NONE when not supplied', () => {
    const { entry, errors } = buildManualEntry(validInput, 'acme');
    expect(errors).toEqual([]);
    expect(entry?.sourceRedactionStrategy).toBe('NONE');
  });

  it('accepts an explicit sourceRedactionStrategy', () => {
    const { entry, errors } = buildManualEntry(
      { ...validInput, sourceRedactionStrategy: 'REDACT_IN_PLACE' },
      'acme'
    );
    expect(errors).toEqual([]);
    expect(entry?.sourceRedactionStrategy).toBe('REDACT_IN_PLACE');
  });

  it('rejects an invalid sourceRedactionStrategy', () => {
    const { entry, errors } = buildManualEntry(
      { ...validInput, sourceRedactionStrategy: 'DELETE_EVERYTHING' as never },
      'acme'
    );
    expect(entry).toBeUndefined();
    expect(errors.some((e) => e.includes('sourceRedactionStrategy'))).toBe(true);
  });

  it('requires userIdColumn when sourceRedactionStrategy is REDACT_IN_PLACE', () => {
    const withoutUserIdColumn = { ...validInput, userIdColumn: undefined };
    const { entry, errors } = buildManualEntry(
      { ...withoutUserIdColumn, sourceRedactionStrategy: 'REDACT_IN_PLACE' },
      'acme'
    );
    expect(entry).toBeUndefined();
    expect(errors.some((e) => e.includes('userIdColumn is required'))).toBe(true);
  });

  it('requires userIdColumn when sourceRedactionStrategy is SHADOW_COPY', () => {
    const withoutUserIdColumn = { ...validInput, userIdColumn: undefined };
    const { entry, errors } = buildManualEntry(
      { ...withoutUserIdColumn, sourceRedactionStrategy: 'SHADOW_COPY' },
      'acme'
    );
    expect(entry).toBeUndefined();
    expect(errors.some((e) => e.includes('userIdColumn is required'))).toBe(true);
  });
});

describe('PiiRegistryService mutation + tenant scoping', () => {
  it('persists through the store and serves the entry to its tenant only', async () => {
    const store = new FakeStore();
    const service = new PiiRegistryService([], store);
    const { entry } = buildManualEntry(validInput, 'acme');
    await service.upsertEntry(entry!);

    expect(store.upserts).toHaveLength(1);
    expect(service.getEntry(validInput.resourceId, 'acme')?.tenantId).toBe('acme');
    // A different tenant must not see acme's declaration.
    expect(service.getEntry(validInput.resourceId, 'globex')).toBeUndefined();
    expect(service.listEntries({ tenantId: 'globex' })).toHaveLength(0);
  });

  it('keeps global (platform) entries visible to every tenant', () => {
    const globalEntry = buildManualEntry(validInput, 'acme').entry!;
    delete globalEntry.tenantId; // simulate a platform/global entry
    const service = new PiiRegistryService([globalEntry]);
    expect(service.getEntry(validInput.resourceId, 'anyone')).toBeDefined();
  });

  it('refuses to mutate a platform-owned entry', async () => {
    const platformEntry: PiiRegistryEntry = { ...buildManualEntry(validInput, 'acme').entry!, ownerConnector: 'pipelines' };
    const service = new PiiRegistryService([platformEntry]);
    await expect(service.upsertEntry(platformEntry)).rejects.toThrow(/manually declared/);
  });

  it('removes a tenant-owned manual entry', async () => {
    const store = new FakeStore();
    const service = new PiiRegistryService([], store);
    await service.upsertEntry(buildManualEntry(validInput, 'acme').entry!);
    const removed = await service.removeEntry(validInput.resourceId, 'acme');
    expect(removed).toBe(true);
    expect(store.deletes).toHaveLength(1);
    expect(service.getEntry(validInput.resourceId, 'acme')).toBeUndefined();
  });
});

describe('piiRegistryRoutes write API (auth + lifecycle)', () => {
  async function makeApp() {
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService([], new FakeStore()),
      writeToken: WRITE_TOKEN,
    });
    return app;
  }

  it('rejects a write without the bearer token', async () => {
    const app = await makeApp();
    const res = await app.inject({ method: 'POST', url: '/pii-registry/resources', payload: validInput });
    expect(res.statusCode).toBe(401);
    await app.close();
  });

  it('disables writes entirely when no token is configured', async () => {
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, { piiRegistryService: new PiiRegistryService([], new FakeStore()) });
    const res = await app.inject({
      method: 'POST',
      url: '/pii-registry/resources',
      headers: { authorization: 'Bearer anything' },
      payload: validInput,
    });
    expect(res.statusCode).toBe(503);
    await app.close();
  });

  it('declares, reads back per-tenant, and removes a resource', async () => {
    const app = await makeApp();
    const auth = { authorization: `Bearer ${WRITE_TOKEN}`, 'x-tenant-id': 'acme' };

    const create = await app.inject({ method: 'POST', url: '/pii-registry/resources', headers: auth, payload: validInput });
    expect(create.statusCode).toBe(201);
    expect(JSON.parse(create.body).resource.ownerConnector).toBe('manual');

    // Visible to the declaring tenant...
    const listAcme = await app.inject({ method: 'GET', url: '/pii-registry/resources', headers: { 'x-tenant-id': 'acme' } });
    expect(JSON.parse(listAcme.body).count).toBe(1);
    // ...but not to another tenant.
    const listOther = await app.inject({ method: 'GET', url: '/pii-registry/resources', headers: { 'x-tenant-id': 'globex' } });
    expect(JSON.parse(listOther.body).count).toBe(0);

    const encoded = encodeURIComponent(validInput.resourceId);
    const del = await app.inject({ method: 'DELETE', url: `/pii-registry/resources/${encoded}`, headers: auth });
    expect(del.statusCode).toBe(200);
    const listAfter = await app.inject({ method: 'GET', url: '/pii-registry/resources', headers: { 'x-tenant-id': 'acme' } });
    expect(JSON.parse(listAfter.body).count).toBe(0);

    await app.close();
  });

  it('maintains the SHADOW_COPY view on declare and drops it on removal', async () => {
    const ensureShadowCopy = jest.fn(async () => {});
    const dropShadowCopyIfExists = jest.fn(async () => {});
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService([], new FakeStore()),
      writeToken: WRITE_TOKEN,
      sourceRedactionHook: { ensureShadowCopy, dropShadowCopyIfExists },
    });
    const auth = { authorization: `Bearer ${WRITE_TOKEN}`, 'x-tenant-id': 'acme' };

    const create = await app.inject({
      method: 'POST',
      url: '/pii-registry/resources',
      headers: auth,
      payload: { ...validInput, sourceRedactionStrategy: 'SHADOW_COPY' },
    });
    expect(create.statusCode).toBe(201);
    expect(ensureShadowCopy).toHaveBeenCalledWith(
      expect.objectContaining({ resourceId: validInput.resourceId, sourceRedactionStrategy: 'SHADOW_COPY' })
    );

    const encoded = encodeURIComponent(validInput.resourceId);
    const del = await app.inject({ method: 'DELETE', url: `/pii-registry/resources/${encoded}`, headers: auth });
    expect(del.statusCode).toBe(200);
    expect(dropShadowCopyIfExists).toHaveBeenCalledWith(
      expect.objectContaining({ resourceId: validInput.resourceId })
    );

    await app.close();
  });

  it('surfaces a shadowCopyError without failing the declare when the hook throws', async () => {
    const ensureShadowCopy = jest.fn(async () => {
      throw new Error('permission denied creating view');
    });
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService([], new FakeStore()),
      writeToken: WRITE_TOKEN,
      sourceRedactionHook: { ensureShadowCopy, dropShadowCopyIfExists: jest.fn(async () => {}) },
    });
    const auth = { authorization: `Bearer ${WRITE_TOKEN}`, 'x-tenant-id': 'acme' };

    const create = await app.inject({
      method: 'POST',
      url: '/pii-registry/resources',
      headers: auth,
      payload: { ...validInput, sourceRedactionStrategy: 'SHADOW_COPY' },
    });

    // The declaration itself still succeeds -- the registry entry is the
    // durable source of truth, and the shadow-copy view is best-effort but
    // must never fail silently.
    expect(create.statusCode).toBe(201);
    expect(JSON.parse(create.body).resource.ownerConnector).toBe('manual');
    expect(JSON.parse(create.body).shadowCopyError).toBe('permission denied creating view');

    await app.close();
  });

  it('lists discovery findings and hides ones already declared', async () => {
    const service = new PiiRegistryService([], new FakeStore());
    const finding = {
      resourceId: 'bigquery:acme.fivetran_hubspot.contacts',
      system: 'bigquery',
      registryStatus: 'UNREGISTERED' as const,
      columns: ['email', 'phone'],
      lastSeen: '2026-07-02T00:00:00.000Z',
    };
    const discoverySource = { getWarehouseDiscoveryFindings: async () => [finding] };

    const app = Fastify({ logger: false })
    await app.register(piiRegistryRoutes, { piiRegistryService: service, writeToken: WRITE_TOKEN, discoverySource })

    // Initially the finding is undeclared → surfaced.
    const before = await app.inject({ method: 'GET', url: '/pii-registry/discovery', headers: { 'x-tenant-id': 'acme' } })
    expect(JSON.parse(before.body).count).toBe(1)

    // Declare it, then it should disappear from the discovery queue.
    await app.inject({
      method: 'POST',
      url: '/pii-registry/resources',
      headers: { authorization: `Bearer ${WRITE_TOKEN}`, 'x-tenant-id': 'acme' },
      payload: { ...validInput, resourceId: finding.resourceId },
    })
    const after = await app.inject({ method: 'GET', url: '/pii-registry/discovery', headers: { 'x-tenant-id': 'acme' } })
    expect(JSON.parse(after.body).count).toBe(0)

    await app.close()
  });

  it('returns 400 with issues for an invalid declaration', async () => {
    const app = await makeApp();
    const res = await app.inject({
      method: 'POST',
      url: '/pii-registry/resources',
      headers: { authorization: `Bearer ${WRITE_TOKEN}`, 'x-tenant-id': 'acme' },
      payload: { resourceId: 'bad', system: 'bigquery', piiFields: [] },
    });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).issues.length).toBeGreaterThan(0);
    await app.close();
  });
});
