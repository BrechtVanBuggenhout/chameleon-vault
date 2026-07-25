import { describe, expect, it } from '@jest/globals';
import Fastify from 'fastify';
import { classifyEntry, computeCoverage, toCoverageItems } from '../src/services/pii-coverage.js';
import { PiiRegistryService, type PiiDeclarationStore } from '../src/services/pii-registry-service.js';
import { piiRegistryRoutes } from '../src/routes/pii-registry.js';
import type { PiiRegistryEntry } from '../src/types/pii-registry.js';
import type { WarehouseDiscoveryFinding } from '../src/types/lineage.js';

function entry(overrides: Partial<PiiRegistryEntry> = {}): PiiRegistryEntry {
  return {
    registryVersion: '2026-07-02',
    resourceId: 'bigquery:acme.warehouse.users',
    system: 'bigquery',
    tenantIdColumn: 'tenant_id',
    userIdColumn: 'user_id',
    ownerConnector: 'manual',
    lineageDestination: 'bigquery:acme.warehouse.users',
    deletionStrategy: 'CRYPTO_SHRED',
    handlingPolicy: 'x',
    evidencePointers: [],
    ghostDataScan: { enabled: true, scanMode: 'SAMPLED', patterns: [] },
    piiFields: [{ name: 'email', classification: 'DIRECT_IDENTIFIER', handling: 'ENCRYPT', requiredInMart: false }],
    ...overrides,
  };
}

class NoopStore implements PiiDeclarationStore {
  async upsert(): Promise<void> {}
  async delete(): Promise<void> {}
}

describe('classifyEntry', () => {
  it('PROTECTED when encrypted + crypto-shred + user scope + PASS', () => {
    expect(classifyEntry(entry(), 'PASS').state).toBe('PROTECTED');
  });

  it('PARTIAL when the deletion strategy is not crypto-shred', () => {
    const result = classifyEntry(entry({ deletionStrategy: 'EXTERNAL_WIPE' }), 'PASS');
    expect(result.state).toBe('PARTIAL');
    expect(result.reasons.join(' ')).toContain('EXTERNAL_WIPE');
  });

  it('PROTECTED when the only non-encrypted field is a hash-surrogate system identifier', () => {
    const result = classifyEntry(
      entry({
        piiFields: [
          { name: 'email_token', classification: 'DIRECT_IDENTIFIER', handling: 'TOKENIZE', requiredInMart: false },
          { name: 'user_id', classification: 'SYSTEM_IDENTIFIER', handling: 'HASH_SURROGATE', requiredInMart: false },
        ],
      }),
      'PASS'
    );
    expect(result.state).toBe('PROTECTED');
  });

  it('PARTIAL when a hash surrogate is applied to a real PII field (not a system identifier)', () => {
    const result = classifyEntry(
      entry({
        piiFields: [{ name: 'email', classification: 'DIRECT_IDENTIFIER', handling: 'HASH_SURROGATE', requiredInMart: false }],
      }),
      'PASS'
    );
    expect(result.state).toBe('PARTIAL');
  });

  it('PARTIAL when a field is not key-reversible', () => {
    const result = classifyEntry(
      entry({ piiFields: [{ name: 'ip', classification: 'QUASI_IDENTIFIER', handling: 'REDACT', requiredInMart: false }] }),
      'PASS'
    );
    expect(result.state).toBe('PARTIAL');
  });

  it('EXPOSED when policy FAILs', () => {
    expect(classifyEntry(entry(), 'FAIL').state).toBe('EXPOSED');
  });
});

describe('computeCoverage', () => {
  it('scores protected fully, partial half, exposed zero', () => {
    const report = computeCoverage([
      { resourceId: 'a', system: 'bigquery', state: 'PROTECTED', weight: 3, reasons: [] },
      { resourceId: 'b', system: 'hubspot', state: 'PARTIAL', weight: 5, reasons: [] },
      { resourceId: 'c', system: 'bigquery', state: 'EXPOSED', weight: 5, reasons: [] },
    ]);
    // (3 + 0.5*5) / 13 = 5.5/13 ≈ 42
    expect(report.score).toBe(42);
    expect(report.counts).toEqual({ protected: 1, partial: 1, exposed: 1, total: 3 });
    expect(report.items[0].state).toBe('EXPOSED'); // exposed sorted first
  });

  it('is 100 when there is no known PII surface', () => {
    expect(computeCoverage([]).score).toBe(100);
  });
});

describe('toCoverageItems', () => {
  it('adds undeclared discovery findings as EXPOSED, skipping already-declared ones', () => {
    const discovery: WarehouseDiscoveryFinding[] = [
      { resourceId: 'bigquery:acme.fivetran.contacts', system: 'bigquery', registryStatus: 'UNREGISTERED', columns: ['email', 'phone'], lastSeen: 'x' },
      { resourceId: 'bigquery:acme.warehouse.users', system: 'bigquery', registryStatus: 'DRIFTED', columns: ['x'], lastSeen: 'x' },
    ];
    const items = toCoverageItems([entry()], () => 'PASS', discovery);
    // declared users (PROTECTED) + the undeclared fivetran table (EXPOSED); the drifted
    // one matches a declared resourceId so it is not double-counted here.
    expect(items).toHaveLength(2);
    expect(items.find((i) => i.resourceId.includes('fivetran'))?.state).toBe('EXPOSED');
  });
});

describe('GET /pii-registry/coverage', () => {
  it('returns a composed report over HTTP', async () => {
    const service = new PiiRegistryService([{ ...entry(), tenantId: 'acme' }], new NoopStore());
    const discoverySource = {
      getWarehouseDiscoveryFindings: async (): Promise<WarehouseDiscoveryFinding[]> => [
        { resourceId: 'bigquery:acme.fivetran.contacts', system: 'bigquery', registryStatus: 'UNREGISTERED', columns: ['email'], lastSeen: 'x' },
      ],
    };
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, { piiRegistryService: service, discoverySource });

    const res = await app.inject({ method: 'GET', url: '/pii-registry/coverage', headers: { 'x-tenant-id': 'acme' } });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.counts.total).toBe(2); // 1 declared + 1 undeclared
    expect(typeof body.score).toBe('number');
    expect(body.counts.exposed).toBe(1);
    await app.close();
  });
});
