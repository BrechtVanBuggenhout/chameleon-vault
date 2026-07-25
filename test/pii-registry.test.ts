import { describe, expect, it } from '@jest/globals';
import Fastify from 'fastify';
import { PiiRegistryService } from '../src/services/pii-registry-service.js';
import { piiRegistryRoutes } from '../src/routes/pii-registry.js';
import { devPiiRegistry } from '../src/data/pii-registry.js';
import type { PiiRegistryEntry } from '../src/types/pii-registry.js';

describe('PiiRegistryService', () => {
  it('indexes registry resources and filters by system', () => {
    const service = new PiiRegistryService(devPiiRegistry);

    const bigQueryEntries = service.listEntries({ system: 'bigquery' });

    expect(bigQueryEntries).toHaveLength(5);
    expect(bigQueryEntries.every((entry) => entry.system === 'bigquery')).toBe(true);
  });

  it('keeps raw ingestion internal and out of scan-enabled BigQuery scope', () => {
    const service = new PiiRegistryService(devPiiRegistry);

    const rawUsers = service.getEntry('bigquery:your-gcp-project-id.chameleon_prod.raw_users');
    const scanEnabledBigQueryEntries = service.listEntries({ system: 'bigquery', scanEnabled: true });
    const dbtOwnedBigQueryEntries = service.listEntries({ system: 'bigquery', ownerConnector: 'dbt' });

    expect(rawUsers).toEqual(
      expect.objectContaining({
        ownerConnector: 'pipelines',
        resourceLayer: 'RAW',
        visibility: 'INTERNAL',
        ghostDataScan: expect.objectContaining({ enabled: false }),
      })
    );
    expect(scanEnabledBigQueryEntries.map((entry) => entry.resourceId)).not.toContain(rawUsers?.resourceId);
    expect(dbtOwnedBigQueryEntries.map((entry) => entry.resourceId)).toEqual([
      'bigquery:your-gcp-project-id.chameleon_prod.stg_users',
      'bigquery:your-gcp-project-id.chameleon_prod.dim_users',
      'bigquery:your-gcp-project-id.chameleon_prod.int_customer_activity',
      'bigquery:your-gcp-project-id.chameleon_prod.mart_customer_metrics',
    ]);
  });

  it('passes the dev registry without policy failures', () => {
    const service = new PiiRegistryService(devPiiRegistry);

    const evaluations = service.evaluateAll();

    expect(evaluations.some((evaluation) => evaluation.status === 'FAIL')).toBe(false);
  });

  it('fails marts that expose direct identifiers without aggregate-only handling', () => {
    const unsafeMart: PiiRegistryEntry = {
      registryVersion: '2026-06-19',
      resourceId: 'bigquery:project.dataset.mart_user_export',
      system: 'bigquery',
      tenantIdColumn: 'tenant_id',
      userIdColumn: 'user_id',
      ownerConnector: 'pipelines',
      lineageDestination: 'bigquery:dataset.mart_user_export',
      deletionStrategy: 'CRYPTO_SHRED',
      handlingPolicy: 'mart_unsafe_export',
      evidencePointers: ['dbt:manifest:model.mart_user_export'],
      piiFields: [
        {
          name: 'email',
          classification: 'DIRECT_IDENTIFIER',
          handling: 'ENCRYPT',
          requiredInMart: false,
        },
      ],
      ghostDataScan: {
        enabled: true,
        scanMode: 'SAMPLED',
        patterns: ['EMAIL'],
      },
    };
    const service = new PiiRegistryService([unsafeMart]);

    const evaluation = service.evaluateEntry(unsafeMart);

    expect(evaluation.status).toBe('FAIL');
    expect(evaluation.issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'DIRECT_IDENTIFIER_IN_MART',
          field: 'email',
        }),
      ])
    );
  });
});

describe('piiRegistryRoutes', () => {
  it('lists registry resources over HTTP', async () => {
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService(devPiiRegistry),
    });

    const response = await app.inject({
      method: 'GET',
      url: '/pii-registry/resources?system=bigquery',
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.count).toBe(5);
    expect(body.resources[0]).not.toHaveProperty('sampleValue');

    await app.close();
  });

  it('lists dbt-owned BigQuery models over HTTP', async () => {
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService(devPiiRegistry),
    });

    const response = await app.inject({
      method: 'GET',
      url: '/pii-registry/resources?system=bigquery&ownerConnector=dbt&scanEnabled=true',
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.count).toBe(3);
    expect(body.resources.map((entry: PiiRegistryEntry) => entry.resourceLayer)).toEqual([
      'STAGING',
      'MART',
      'INTERMEDIATE',
    ]);

    await app.close();
  });

  it('returns policy evaluations over HTTP', async () => {
    const app = Fastify({ logger: false });
    await app.register(piiRegistryRoutes, {
      piiRegistryService: new PiiRegistryService(devPiiRegistry),
    });

    const response = await app.inject({
      method: 'GET',
      url: '/pii-registry/policy',
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.status).toBe('WARN');
    expect(body.evaluations).toHaveLength(devPiiRegistry.length);

    await app.close();
  });
});
