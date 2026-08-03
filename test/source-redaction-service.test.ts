import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import { PiiRegistryService } from '../src/services/pii-registry-service.js';
import type { PiiRegistryEntry } from '../src/types/pii-registry.js';

const mockGetQueryResults = jest.fn(async () => [[]]);
let queryMetadata: Record<string, unknown> = { statistics: { query: { numDmlAffectedRows: '1' } } };
const mockGetMetadata = jest.fn(async () => [queryMetadata]);
const mockJob = { getQueryResults: mockGetQueryResults, getMetadata: mockGetMetadata };
const mockCreateQueryJob = jest.fn(async () => [mockJob]);

await jest.unstable_mockModule('@google-cloud/bigquery', () => ({
  BigQuery: class {
    createQueryJob = mockCreateQueryJob;
  },
}));

const { SourceRedactionService } = await import('../src/services/source-redaction-service.js');
const { BigQuery } = await import('@google-cloud/bigquery');

function makeManualEntry(overrides: Partial<PiiRegistryEntry>): PiiRegistryEntry {
  return {
    registryVersion: '2026-08-04',
    resourceId: 'bigquery:acme-project.crm.contacts',
    system: 'bigquery',
    tenantIdColumn: 'tenant_id',
    userIdColumn: 'user_id',
    piiFields: [
      { name: 'email', classification: 'DIRECT_IDENTIFIER', handling: 'ENCRYPT', requiredInMart: false },
    ],
    ownerConnector: 'manual',
    lineageDestination: 'bigquery:acme-project.crm.contacts',
    deletionStrategy: 'CRYPTO_SHRED',
    sourceRedactionStrategy: 'REDACT_IN_PLACE',
    ghostDataScan: { enabled: true, scanMode: 'SAMPLED', patterns: [] },
    handlingPolicy: 'manual_declaration',
    evidencePointers: [],
    tenantId: 'acme',
    ...overrides,
  };
}

describe('SourceRedactionService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    queryMetadata = { statistics: { query: { numDmlAffectedRows: '1' } } };
  });

  describe('planRedaction', () => {
    it('finds only manual, REDACT_IN_PLACE-opted-in resources for the tenant', () => {
      const registry = new PiiRegistryService([
        makeManualEntry({ resourceId: 'bigquery:acme.crm.contacts' }),
        makeManualEntry({ resourceId: 'bigquery:acme.crm.leads', sourceRedactionStrategy: 'NONE' }),
        makeManualEntry({ resourceId: 'bigquery:acme.crm.other_tenant', tenantId: 'other-tenant' }),
        makeManualEntry({ resourceId: 'bigquery:acme.crm.shadow', sourceRedactionStrategy: 'SHADOW_COPY' }),
      ]);
      const service = new SourceRedactionService(registry, new BigQuery());

      const plan = service.planRedaction('acme');

      expect(plan.map((e) => e.resourceId)).toEqual(['bigquery:acme.crm.contacts']);
    });
  });

  describe('redactUserInDeclaredSources', () => {
    it('returns an empty result when no resources are opted in', async () => {
      const registry = new PiiRegistryService([]);
      const service = new SourceRedactionService(registry, new BigQuery());

      const results = await service.redactUserInDeclaredSources('user-1', 'acme');

      expect(results).toEqual([]);
      expect(mockCreateQueryJob).not.toHaveBeenCalled();
    });

    it('builds a correctly-scoped UPDATE and returns rowsAffected on success', async () => {
      const registry = new PiiRegistryService([
        makeManualEntry({ resourceId: 'bigquery:acme-project.crm.contacts' }),
      ]);
      const service = new SourceRedactionService(registry, new BigQuery());
      queryMetadata = { statistics: { query: { numDmlAffectedRows: '3' } } };

      const results = await service.redactUserInDeclaredSources('user-1', 'acme');

      expect(mockCreateQueryJob).toHaveBeenCalledWith({
        query: 'UPDATE `acme-project.crm.contacts` SET email = NULL WHERE user_id = @userId AND tenant_id = @tenantId',
        params: { userId: 'user-1', tenantId: 'acme' },
      });
      expect(results).toEqual([
        { resourceId: 'bigquery:acme-project.crm.contacts', success: true, rowsAffected: 3 },
      ]);
    });

    it('omits the tenant clause when the resource has no tenantIdColumn declared', async () => {
      const registry = new PiiRegistryService([
        makeManualEntry({ resourceId: 'bigquery:acme-project.crm.contacts', tenantIdColumn: undefined }),
      ]);
      const service = new SourceRedactionService(registry, new BigQuery());

      await service.redactUserInDeclaredSources('user-1', 'acme');

      expect(mockCreateQueryJob).toHaveBeenCalledWith({
        query: 'UPDATE `acme-project.crm.contacts` SET email = NULL WHERE user_id = @userId',
        params: { userId: 'user-1' },
      });
    });

    it('redacts every declared PII field, not just the first', async () => {
      const registry = new PiiRegistryService([
        makeManualEntry({
          resourceId: 'bigquery:acme-project.crm.contacts',
          piiFields: [
            { name: 'email', classification: 'DIRECT_IDENTIFIER', handling: 'ENCRYPT', requiredInMart: false },
            { name: 'phone', classification: 'CONTACT', handling: 'ENCRYPT', requiredInMart: false },
          ],
        }),
      ]);
      const service = new SourceRedactionService(registry, new BigQuery());

      await service.redactUserInDeclaredSources('user-1', 'acme');

      expect(mockCreateQueryJob).toHaveBeenCalledWith(
        expect.objectContaining({ query: expect.stringContaining('SET email = NULL, phone = NULL') })
      );
    });

    it('fails one resource without aborting the others', async () => {
      const registry = new PiiRegistryService([
        makeManualEntry({ resourceId: 'bigquery:acme-project.crm.contacts' }),
        makeManualEntry({ resourceId: 'salesforce:leads', system: 'salesforce' }),
      ]);
      const service = new SourceRedactionService(registry, new BigQuery());

      const results = await service.redactUserInDeclaredSources('user-1', 'acme');

      expect(results).toEqual([
        { resourceId: 'bigquery:acme-project.crm.contacts', success: true, rowsAffected: 1 },
        {
          resourceId: 'salesforce:leads',
          success: false,
          error: 'sourceRedactionStrategy REDACT_IN_PLACE is only implemented for bigquery resources, got "salesforce".',
        },
      ]);
    });

    it('refuses to run a redaction with an unsafe field identifier, without ever attempting the query', async () => {
      const registry = new PiiRegistryService([
        makeManualEntry({
          piiFields: [
            { name: 'email); DROP TABLE users; --', classification: 'DIRECT_IDENTIFIER', handling: 'ENCRYPT', requiredInMart: false },
          ],
        }),
      ]);
      const service = new SourceRedactionService(registry, new BigQuery());

      const results = await service.redactUserInDeclaredSources('user-1', 'acme');

      expect(results[0].success).toBe(false);
      expect(results[0].error).toContain('is not a safe column identifier');
      expect(mockCreateQueryJob).not.toHaveBeenCalled();
    });

    it('refuses to run a redaction with an unsafe userIdColumn identifier', async () => {
      const registry = new PiiRegistryService([
        makeManualEntry({ userIdColumn: 'user-id; DROP TABLE users; --' }),
      ]);
      const service = new SourceRedactionService(registry, new BigQuery());

      const results = await service.redactUserInDeclaredSources('user-1', 'acme');

      expect(results[0].success).toBe(false);
      expect(results[0].error).toContain('is not a safe column identifier');
      expect(mockCreateQueryJob).not.toHaveBeenCalled();
    });
  });
});
