import { describe, expect, it, jest } from '@jest/globals';
import Fastify from 'fastify';
import { PiiRegistryService, type PiiDeclarationStore } from '../src/services/pii-registry-service.js';
import { buildManualEntry } from '../src/services/pii-registry-validation.js';
import { piiRegistryRoutes } from '../src/routes/pii-registry.js';
import { getRequestContext } from '../src/middleware/request-logging.js';
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

  // Real bug, confirmed twice against live customer data (agencyAndOfficeMigration,
  // then federated_user): declaring the same column as both userIdColumn and
  // tenantIdColumn silently breaks tenant-scoped reads for every row synced
  // under it. See pii-registry-validation.ts's comment on this check.
  it('rejects tenantIdColumn being the same column as userIdColumn', () => {
    const { entry, errors } = buildManualEntry(
      { ...validInput, userIdColumn: 'office_ref', tenantIdColumn: 'office_ref' },
      'acme'
    );
    expect(entry).toBeUndefined();
    expect(errors.some((e) => e.includes('cannot be the same column'))).toBe(true);
  });

  it('allows userIdColumn and tenantIdColumn to differ', () => {
    const { entry, errors } = buildManualEntry(
      { ...validInput, userIdColumn: 'user_id', tenantIdColumn: 'tenant_id' },
      'acme'
    );
    expect(errors).toEqual([]);
    expect(entry?.userIdColumn).toBe('user_id');
    expect(entry?.tenantIdColumn).toBe('tenant_id');
  });

  it('allows tenantIdColumn to be entirely unset (the correct single-tenant declaration)', () => {
    const { entry, errors } = buildManualEntry(
      { ...validInput, userIdColumn: 'user_id', tenantIdColumn: undefined },
      'acme'
    );
    expect(errors).toEqual([]);
    expect(entry?.tenantIdColumn).toBeUndefined();
  });

  it('stamps declaredBy and lastModifiedBy on first declare when an actor is resolved', () => {
    const { entry } = buildManualEntry(validInput, 'acme', new Date(), undefined, 'analyst@example.com');
    expect(entry?.declaredBy).toBe('analyst@example.com');
    expect(entry?.lastModifiedBy).toBe('analyst@example.com');
  });

  it('leaves declaredBy/lastModifiedBy unset when no actor is resolved (shared write token)', () => {
    const { entry } = buildManualEntry(validInput, 'acme');
    expect(entry?.declaredBy).toBeUndefined();
    expect(entry?.lastModifiedBy).toBeUndefined();
  });

  it('preserves the original declaredBy across an update by a different actor, but updates lastModifiedBy', () => {
    const declared = buildManualEntry(validInput, 'acme', new Date(), undefined, 'first@example.com').entry!;
    const updated = buildManualEntry(validInput, 'acme', new Date(), declared, 'second@example.com').entry!;
    expect(updated.declaredBy).toBe('first@example.com');
    expect(updated.lastModifiedBy).toBe('second@example.com');
  });

  it('clears lastModifiedBy (does not carry it forward) when an update has no resolvable actor', () => {
    const declared = buildManualEntry(validInput, 'acme', new Date(), undefined, 'first@example.com').entry!;
    const updated = buildManualEntry(validInput, 'acme', new Date(), declared).entry!;
    expect(updated.declaredBy).toBe('first@example.com');
    expect(updated.lastModifiedBy).toBeUndefined();
  });

  describe('sourceRedactionStrategies (array, combinable)', () => {
    it('defaults to an empty array when nothing is declared', () => {
      const { entry, errors } = buildManualEntry(validInput, 'acme');
      expect(errors).toEqual([]);
      expect(entry?.sourceRedactionStrategies).toEqual([]);
    });

    it('accepts multiple strategies together', () => {
      const { entry, errors } = buildManualEntry(
        { ...validInput, sourceRedactionStrategies: ['REDACT_IN_PLACE', 'ENCRYPTED_COPY'] },
        'acme'
      );
      expect(errors).toEqual([]);
      expect(entry?.sourceRedactionStrategies).toEqual(['REDACT_IN_PLACE', 'ENCRYPTED_COPY']);
    });

    it('accepts ENCRYPTED_COPY alone', () => {
      const { entry, errors } = buildManualEntry(
        { ...validInput, sourceRedactionStrategies: ['ENCRYPTED_COPY'] },
        'acme'
      );
      expect(errors).toEqual([]);
      expect(entry?.sourceRedactionStrategies).toEqual(['ENCRYPTED_COPY']);
    });

    it('rejects NONE inside the array -- an empty array is the array field\'s "none"', () => {
      const { entry, errors } = buildManualEntry(
        { ...validInput, sourceRedactionStrategies: ['NONE' as never] },
        'acme'
      );
      expect(entry).toBeUndefined();
      expect(errors.some((e) => e.includes('sourceRedactionStrategies[0]'))).toBe(true);
    });

    it('rejects an unknown value inside the array', () => {
      const { entry, errors } = buildManualEntry(
        { ...validInput, sourceRedactionStrategies: ['DELETE_EVERYTHING' as never] },
        'acme'
      );
      expect(entry).toBeUndefined();
      expect(errors.some((e) => e.includes('sourceRedactionStrategies[0]'))).toBe(true);
    });

    it('an empty array is accepted as the new none-state', () => {
      const { entry, errors } = buildManualEntry(
        { ...validInput, sourceRedactionStrategies: [] },
        'acme'
      );
      expect(errors).toEqual([]);
      expect(entry?.sourceRedactionStrategies).toEqual([]);
    });

    it('requires userIdColumn when only ENCRYPTED_COPY is set (via the array, not the legacy field)', () => {
      const { entry, errors } = buildManualEntry(
        { ...validInput, userIdColumn: undefined, sourceRedactionStrategies: ['ENCRYPTED_COPY'] },
        'acme'
      );
      expect(entry).toBeUndefined();
      expect(errors.some((e) => e.includes('userIdColumn is required'))).toBe(true);
    });

    it('legacy singular-field-only entries still normalize via the array on read', () => {
      // Simulates an entry declared before the array field existed --
      // buildManualEntry itself always writes the array going forward, but
      // resolveSourceRedactionStrategies must still make sense of an entry
      // that only ever had the singular field.
      const { entry } = buildManualEntry(
        { ...validInput, sourceRedactionStrategy: 'SHADOW_COPY' },
        'acme'
      );
      expect(entry?.sourceRedactionStrategies).toEqual(['SHADOW_COPY']);
    });
  });

  describe('pubsub declarations', () => {
    const validPubsubInput: PiiRegistryDeclarationInput = {
      resourceId: 'pubsub:acme-project.cdc-events',
      system: 'pubsub',
      pubsubAllowedCallerServiceAccount: '123456789012345678901',
      userIdFieldPath: 'after.user_id',
      piiFields: [{ name: 'after.email', classification: 'DIRECT_IDENTIFIER', handling: 'ENCRYPT' }],
    };

    it('accepts a pubsub declaration with both required fields set', () => {
      const { entry, errors } = buildManualEntry(validPubsubInput, 'acme');
      expect(errors).toEqual([]);
      expect(entry?.system).toBe('pubsub');
      expect(entry?.pubsubAllowedCallerServiceAccount).toBe('123456789012345678901');
      expect(entry?.userIdFieldPath).toBe('after.user_id');
      expect(entry?.piiFields[0].name).toBe('after.email');
    });

    it('rejects a pubsub declaration missing pubsubAllowedCallerServiceAccount', () => {
      const { entry, errors } = buildManualEntry(
        { ...validPubsubInput, pubsubAllowedCallerServiceAccount: undefined },
        'acme'
      );
      expect(entry).toBeUndefined();
      expect(errors).toContain('pubsubAllowedCallerServiceAccount is required when system is pubsub.');
    });

    it('rejects a pubsub declaration missing userIdFieldPath', () => {
      const { entry, errors } = buildManualEntry(
        { ...validPubsubInput, userIdFieldPath: undefined },
        'acme'
      );
      expect(entry).toBeUndefined();
      expect(errors).toContain('userIdFieldPath is required when system is pubsub.');
    });

    it('does not require pubsubAllowedCallerServiceAccount/userIdFieldPath for non-pubsub systems', () => {
      const { errors } = buildManualEntry(validInput, 'acme');
      expect(errors).toEqual([]);
    });
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
      sourceRedactionHook: { ensureShadowCopy, dropShadowCopyIfExists, ensureEncryptedCopyTable: jest.fn(async () => {}) },
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
      sourceRedactionHook: {
        ensureShadowCopy,
        dropShadowCopyIfExists: jest.fn(async () => {}),
        ensureEncryptedCopyTable: jest.fn(async () => {}),
      },
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

  it('calls ensureEncryptedCopyTable on declare when ENCRYPTED_COPY is in sourceRedactionStrategies', async () => {
    const ensureEncryptedCopyTable = jest.fn(async () => {});
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService([], new FakeStore()),
      writeToken: WRITE_TOKEN,
      sourceRedactionHook: {
        ensureShadowCopy: jest.fn(async () => {}),
        dropShadowCopyIfExists: jest.fn(async () => {}),
        ensureEncryptedCopyTable,
      },
    });
    const auth = { authorization: `Bearer ${WRITE_TOKEN}`, 'x-tenant-id': 'acme' };

    const create = await app.inject({
      method: 'POST',
      url: '/pii-registry/resources',
      headers: auth,
      payload: { ...validInput, sourceRedactionStrategies: ['ENCRYPTED_COPY'] },
    });

    expect(create.statusCode).toBe(201);
    expect(ensureEncryptedCopyTable).toHaveBeenCalledWith(
      expect.objectContaining({ resourceId: validInput.resourceId, sourceRedactionStrategies: ['ENCRYPTED_COPY'] })
    );

    await app.close();
  });

  it('surfaces an encryptedCopyError without failing the declare when the hook throws', async () => {
    const ensureEncryptedCopyTable = jest.fn(async () => {
      throw new Error('permission denied creating table');
    });
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService([], new FakeStore()),
      writeToken: WRITE_TOKEN,
      sourceRedactionHook: {
        ensureShadowCopy: jest.fn(async () => {}),
        dropShadowCopyIfExists: jest.fn(async () => {}),
        ensureEncryptedCopyTable,
      },
    });
    const auth = { authorization: `Bearer ${WRITE_TOKEN}`, 'x-tenant-id': 'acme' };

    const create = await app.inject({
      method: 'POST',
      url: '/pii-registry/resources',
      headers: auth,
      payload: { ...validInput, sourceRedactionStrategies: ['ENCRYPTED_COPY'] },
    });

    expect(create.statusCode).toBe(201);
    expect(JSON.parse(create.body).resource.ownerConnector).toBe('manual');
    expect(JSON.parse(create.body).encryptedCopyError).toBe('permission denied creating table');

    await app.close();
  });

  it('rejects REDACT_IN_PLACE declared against a confirmed BigQuery VIEW', async () => {
    const getColumns = jest.fn(async () => []);
    const getTableType = jest.fn(async () => 'VIEW');
    const store = new FakeStore();
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService([], store),
      writeToken: WRITE_TOKEN,
      schemaSource: { getColumns, getTableType },
    });
    const auth = { authorization: `Bearer ${WRITE_TOKEN}`, 'x-tenant-id': 'acme' };

    const create = await app.inject({
      method: 'POST',
      url: '/pii-registry/resources',
      headers: auth,
      payload: { ...validInput, sourceRedactionStrategy: 'REDACT_IN_PLACE' },
    });

    expect(create.statusCode).toBe(400);
    expect(JSON.parse(create.body).error).toContain('is a view');
    expect(getTableType).toHaveBeenCalledWith(validInput.resourceId);
    // Never even reached the store -- rejected before persisting.
    expect(store.upserts).toHaveLength(0);

    await app.close();
  });

  it('allows REDACT_IN_PLACE against a confirmed real BASE TABLE', async () => {
    const getColumns = jest.fn(async () => []);
    const getTableType = jest.fn(async () => 'BASE TABLE');
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService([], new FakeStore()),
      writeToken: WRITE_TOKEN,
      schemaSource: { getColumns, getTableType },
    });
    const auth = { authorization: `Bearer ${WRITE_TOKEN}`, 'x-tenant-id': 'acme' };

    const create = await app.inject({
      method: 'POST',
      url: '/pii-registry/resources',
      headers: auth,
      payload: { ...validInput, sourceRedactionStrategy: 'REDACT_IN_PLACE' },
    });

    expect(create.statusCode).toBe(201);
    expect(JSON.parse(create.body).resource.sourceRedactionStrategy).toBe('REDACT_IN_PLACE');

    await app.close();
  });

  it('fails open (declare still succeeds) when the table-type check itself errors', async () => {
    const getColumns = jest.fn(async () => []);
    const getTableType = jest.fn(async () => {
      throw new Error('BigQuery unavailable');
    });
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService([], new FakeStore()),
      writeToken: WRITE_TOKEN,
      schemaSource: { getColumns, getTableType },
    });
    const auth = { authorization: `Bearer ${WRITE_TOKEN}`, 'x-tenant-id': 'acme' };

    const create = await app.inject({
      method: 'POST',
      url: '/pii-registry/resources',
      headers: auth,
      payload: { ...validInput, sourceRedactionStrategy: 'REDACT_IN_PLACE' },
    });

    // A schema-check hiccup must never block an otherwise-valid declare --
    // this is a guard against one specific known failure mode, not a
    // general existence/permissions gate.
    expect(create.statusCode).toBe(201);

    await app.close();
  });

  it('skips the table-type check entirely when schemaSource has no getTableType (older/unconfigured deployments)', async () => {
    const getColumns = jest.fn(async () => []);
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService([], new FakeStore()),
      writeToken: WRITE_TOKEN,
      schemaSource: { getColumns },
    });
    const auth = { authorization: `Bearer ${WRITE_TOKEN}`, 'x-tenant-id': 'acme' };

    const create = await app.inject({
      method: 'POST',
      url: '/pii-registry/resources',
      headers: auth,
      payload: { ...validInput, sourceRedactionStrategy: 'REDACT_IN_PLACE' },
    });

    expect(create.statusCode).toBe(201);

    await app.close();
  });

  it('rejects REDACT_IN_PLACE when userIdColumn does not exist on the real table', async () => {
    // Reproduces a real live bug: a resource declared with userIdColumn
    // "user_id" against a table that has no such column at all (a PII-scan
    // metadata table, not per-user data) -- BigQuery rejected the deletion-
    // time UPDATE with "Unrecognized name: user_id", and because the
    // cascade evaluates every REDACT_IN_PLACE resource on every deletion
    // regardless of that resource's own users, this single bad declaration
    // blocked deletions tenant-wide.
    const getColumns = jest.fn(async () => [
      { name: 'resource_id', dataType: 'STRING', nullable: false, ordinalPosition: 1 },
      { name: 'tenant_id', dataType: 'STRING', nullable: false, ordinalPosition: 2 },
      { name: 'email', dataType: 'STRING', nullable: true, ordinalPosition: 3 },
    ]);
    const store = new FakeStore();
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService([], store),
      writeToken: WRITE_TOKEN,
      schemaSource: { getColumns },
    });
    const auth = { authorization: `Bearer ${WRITE_TOKEN}`, 'x-tenant-id': 'acme' };

    const create = await app.inject({
      method: 'POST',
      url: '/pii-registry/resources',
      headers: auth,
      payload: { ...validInput, sourceRedactionStrategy: 'REDACT_IN_PLACE' },
    });

    expect(create.statusCode).toBe(400);
    expect(JSON.parse(create.body).error).toContain("don't exist");
    expect(JSON.parse(create.body).error).toContain('user_id');
    expect(store.upserts).toHaveLength(0);

    await app.close();
  });

  it('lists every missing column, not just the first, and reports the real columns available', async () => {
    const getColumns = jest.fn(async () => [{ name: 'resource_id', dataType: 'STRING', nullable: false, ordinalPosition: 1 }]);
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService([], new FakeStore()),
      writeToken: WRITE_TOKEN,
      schemaSource: { getColumns },
    });
    const auth = { authorization: `Bearer ${WRITE_TOKEN}`, 'x-tenant-id': 'acme' };

    const create = await app.inject({
      method: 'POST',
      url: '/pii-registry/resources',
      headers: auth,
      payload: { ...validInput, sourceRedactionStrategy: 'SHADOW_COPY' },
    });

    expect(create.statusCode).toBe(400);
    const error = JSON.parse(create.body).error as string;
    // userIdColumn, tenantIdColumn, and the declared "email" field are all
    // missing from the real (single-column) schema.
    expect(error).toContain('user_id');
    expect(error).toContain('tenant_id');
    expect(error).toContain('email');
    expect(error).toContain('resource_id'); // the one real column, listed for context

    await app.close();
  });

  it('allows REDACT_IN_PLACE when every referenced column genuinely exists', async () => {
    const getColumns = jest.fn(async () => [
      { name: 'user_id', dataType: 'STRING', nullable: false, ordinalPosition: 1 },
      { name: 'tenant_id', dataType: 'STRING', nullable: false, ordinalPosition: 2 },
      { name: 'email', dataType: 'STRING', nullable: true, ordinalPosition: 3 },
    ]);
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService([], new FakeStore()),
      writeToken: WRITE_TOKEN,
      schemaSource: { getColumns },
    });
    const auth = { authorization: `Bearer ${WRITE_TOKEN}`, 'x-tenant-id': 'acme' };

    const create = await app.inject({
      method: 'POST',
      url: '/pii-registry/resources',
      headers: auth,
      payload: { ...validInput, sourceRedactionStrategy: 'REDACT_IN_PLACE' },
    });

    expect(create.statusCode).toBe(201);

    await app.close();
  });

  it('skips the column-existence check for sourceRedactionStrategy NONE', async () => {
    // NONE never generates SQL referencing these columns, so a resource
    // without a real userIdColumn (e.g. a system/metadata table) must still
    // be declarable with the default strategy.
    const getColumns = jest.fn(async () => [{ name: 'resource_id', dataType: 'STRING', nullable: false, ordinalPosition: 1 }]);
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService([], new FakeStore()),
      writeToken: WRITE_TOKEN,
      schemaSource: { getColumns },
    });
    const auth = { authorization: `Bearer ${WRITE_TOKEN}`, 'x-tenant-id': 'acme' };

    const create = await app.inject({
      method: 'POST',
      url: '/pii-registry/resources',
      headers: auth,
      payload: { ...validInput, sourceRedactionStrategy: 'NONE' },
    });

    expect(create.statusCode).toBe(201);
    expect(getColumns).not.toHaveBeenCalled();

    await app.close();
  });

  it('fails open on the column-existence check when getColumns returns empty (table not found, or schema-check failure)', async () => {
    const getColumns = jest.fn(async () => []);
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService([], new FakeStore()),
      writeToken: WRITE_TOKEN,
      schemaSource: { getColumns },
    });
    const auth = { authorization: `Bearer ${WRITE_TOKEN}`, 'x-tenant-id': 'acme' };

    const create = await app.inject({
      method: 'POST',
      url: '/pii-registry/resources',
      headers: auth,
      payload: { ...validInput, sourceRedactionStrategy: 'REDACT_IN_PLACE' },
    });

    expect(create.statusCode).toBe(201);

    await app.close();
  });

  it('fails open on the column-existence check when getColumns itself throws', async () => {
    const getColumns = jest.fn(async () => {
      throw new Error('BigQuery unavailable');
    });
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService([], new FakeStore()),
      writeToken: WRITE_TOKEN,
      schemaSource: { getColumns },
    });
    const auth = { authorization: `Bearer ${WRITE_TOKEN}`, 'x-tenant-id': 'acme' };

    const create = await app.inject({
      method: 'POST',
      url: '/pii-registry/resources',
      headers: auth,
      payload: { ...validInput, sourceRedactionStrategy: 'REDACT_IN_PLACE' },
    });

    expect(create.statusCode).toBe(201);

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

  it('accepts a write with no bearer token when an analyst identity was already resolved upstream, and stamps declaredBy/lastModifiedBy', async () => {
    // Simulates what main.ts's global onRequest auth hook does when it
    // resolves a valid analyst/console-session credential on an
    // ANALYST_CREDENTIAL_*-allowed path -- this test registers piiRegistryRoutes
    // in isolation, so it reproduces that upstream effect directly rather
    // than exercising the full app + real credential resolution.
    const app = Fastify({ logger: false });
    app.addHook('onRequest', async (request) => {
      if (request.headers['x-simulated-analyst-email']) {
        getRequestContext(request).analystEmail = request.headers['x-simulated-analyst-email'] as string;
      }
    });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService([], new FakeStore()),
      writeToken: WRITE_TOKEN,
    });

    const res = await app.inject({
      method: 'POST',
      url: '/pii-registry/resources',
      // No Authorization header at all -- only the simulated upstream identity.
      headers: { 'x-tenant-id': 'acme', 'x-simulated-analyst-email': 'analyst@example.com' },
      payload: validInput,
    });

    expect(res.statusCode).toBe(201);
    const resource = JSON.parse(res.body).resource;
    expect(resource.declaredBy).toBe('analyst@example.com');
    expect(resource.lastModifiedBy).toBe('analyst@example.com');

    await app.close();
  });
});
