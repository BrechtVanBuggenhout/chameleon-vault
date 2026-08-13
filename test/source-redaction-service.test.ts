import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import { PiiRegistryService } from '../src/services/pii-registry-service.js';
import type { PiiRegistryEntry } from '../src/types/pii-registry.js';

const mockGetQueryResults = jest.fn(async () => [[]]);
let queryMetadata: Record<string, unknown> = { statistics: { query: { numDmlAffectedRows: '1' } } };
const mockGetMetadata = jest.fn(async () => [queryMetadata]);
const mockJob = { getQueryResults: mockGetQueryResults, getMetadata: mockGetMetadata };
const mockCreateQueryJob = jest.fn(async () => [mockJob]);

// Defaults to "already gone" (404) -- the common case, since
// ensureShadowCopy always calls dropShadowCopyIfExists first as its
// idempotent-replace step, and most tests aren't exercising that path.
let deleteTableShouldFail: { code: number } | undefined = { code: 404 };
const mockDeleteTable = jest.fn(async () => {
  if (deleteTableShouldFail) throw deleteTableShouldFail;
  return [{}];
});
const mockCreateTable = jest.fn(async () => [{}]);
const mockTable = jest.fn(() => ({ delete: mockDeleteTable }));
const mockDataset = jest.fn(() => ({ createTable: mockCreateTable, table: mockTable }));

await jest.unstable_mockModule('@google-cloud/bigquery', () => ({
  BigQuery: class {
    createQueryJob = mockCreateQueryJob;
    dataset = mockDataset;
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
    deleteTableShouldFail = { code: 404 };
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
      expect(results[0].error).toContain('not a safe column/table name');
      expect(mockCreateQueryJob).not.toHaveBeenCalled();
    });

    it('refuses to run a redaction with an unsafe userIdColumn identifier', async () => {
      const registry = new PiiRegistryService([
        makeManualEntry({ userIdColumn: 'user-id; DROP TABLE users; --' }),
      ]);
      const service = new SourceRedactionService(registry, new BigQuery());

      const results = await service.redactUserInDeclaredSources('user-1', 'acme');

      expect(results[0].success).toBe(false);
      expect(results[0].error).toContain('not a safe column/table name');
      expect(mockCreateQueryJob).not.toHaveBeenCalled();
    });
  });

  describe('ensureShadowCopy / dropShadowCopyIfExists', () => {
    const PII_VAULT_RESOURCE_ID = 'bigquery:chameleon-proj.chameleon_dev.pii_vault';
    const BATCH_DECRYPT_FN = 'chameleon-proj.decrypted_views.chameleon_batch_decrypt';

    it('drops any existing shadow view and does not create one when the strategy is not SHADOW_COPY', async () => {
      const registry = new PiiRegistryService([]);
      const service = new SourceRedactionService(
        registry, new BigQuery(), PII_VAULT_RESOURCE_ID, BATCH_DECRYPT_FN
      );
      const resource = makeManualEntry({ sourceRedactionStrategy: 'NONE' });

      await service.ensureShadowCopy(resource);

      expect(mockDataset).toHaveBeenCalledWith('crm', { projectId: 'acme-project' });
      expect(mockTable).toHaveBeenCalledWith('contacts_deidentified');
      expect(mockDeleteTable).toHaveBeenCalled();
      expect(mockCreateTable).not.toHaveBeenCalled();
    });

    it('refuses SHADOW_COPY when pii_vault / batch-decrypt are not configured on this deployment', async () => {
      const registry = new PiiRegistryService([]);
      // No piiVaultResourceId/batchDecryptFunctionRef passed at all.
      const service = new SourceRedactionService(registry, new BigQuery());
      const resource = makeManualEntry({ sourceRedactionStrategy: 'SHADOW_COPY' });

      await expect(service.ensureShadowCopy(resource)).rejects.toThrow(
        'SHADOW_COPY requires decrypted views to be enabled'
      );
      expect(mockCreateTable).not.toHaveBeenCalled();
    });

    it('creates a view joining the source table against pii_vault, excepting the declared PII columns', async () => {
      const registry = new PiiRegistryService([]);
      const service = new SourceRedactionService(
        registry, new BigQuery(), PII_VAULT_RESOURCE_ID, BATCH_DECRYPT_FN
      );
      const resource = makeManualEntry({
        resourceId: 'bigquery:acme-project.crm.contacts',
        sourceRedactionStrategy: 'SHADOW_COPY',
        piiFields: [
          { name: 'email', classification: 'DIRECT_IDENTIFIER', handling: 'ENCRYPT', requiredInMart: false },
          { name: 'phone', classification: 'CONTACT', handling: 'ENCRYPT', requiredInMart: false },
        ],
      });

      await service.ensureShadowCopy(resource);

      // Idempotent-replace: always deletes any prior view first.
      expect(mockDataset).toHaveBeenCalledWith('crm', { projectId: 'acme-project' });
      expect(mockDeleteTable).toHaveBeenCalled();

      expect(mockCreateTable).toHaveBeenCalledWith(
        'contacts_deidentified',
        expect.objectContaining({
          view: expect.stringMatching(
            /WITH decrypted_pii AS \([\s\S]*FROM `chameleon-proj\.chameleon_dev\.pii_vault`[\s\S]*WHERE tenant_id = 'acme'/
          ),
        })
      );
      const [, { view: viewSql }] = mockCreateTable.mock.calls[mockCreateTable.mock.calls.length - 1] as [string, { view: string }];
      expect(viewSql).toContain('SELECT s.* EXCEPT (email, phone), d.email, d.phone');
      expect(viewSql).toContain('FROM `acme-project.crm.contacts` s');
      expect(viewSql).toContain('LEFT JOIN decrypted_pii d ON s.user_id = d.user_id');
      expect(viewSql).toContain("WHERE s.tenant_id = 'acme'");
    });

    it('excludes non-ENCRYPT fields from the pivot, since only ENCRYPT fields are ever synced into pii_vault', async () => {
      const registry = new PiiRegistryService([]);
      const service = new SourceRedactionService(
        registry, new BigQuery(), PII_VAULT_RESOURCE_ID, BATCH_DECRYPT_FN
      );
      // Reproduces a real live bug: a declared field literally named
      // "user_id" with handling HASH_SURROGATE (not ENCRYPT) collided with
      // the CTE's own `user_id` column and made BigQuery reject the whole
      // view as an ambiguous GROUP BY. Even setting the crash aside, a
      // HASH_SURROGATE/SYSTEM_IDENTIFIER field is never written to
      // pii_vault as a field_name row, so pivoting it always resolves to
      // NULL -- silently overwriting a real system column with NULL had
      // this not crashed first.
      const resource = makeManualEntry({
        resourceId: 'bigquery:acme-project.crm.contacts',
        sourceRedactionStrategy: 'SHADOW_COPY',
        piiFields: [
          { name: 'user_id', classification: 'SYSTEM_IDENTIFIER', handling: 'HASH_SURROGATE', requiredInMart: false },
          { name: 'email', classification: 'DIRECT_IDENTIFIER', handling: 'ENCRYPT', requiredInMart: false },
        ],
      });

      await service.ensureShadowCopy(resource);

      const [, { view: viewSql }] = mockCreateTable.mock.calls[0] as [string, { view: string }];
      expect(viewSql).toContain('SELECT s.* EXCEPT (email), d.email');
      // The join condition's `d.user_id` legitimately references the CTE's
      // own raw `user_id` column -- what must NOT appear is a second,
      // pivoted `AS user_id` alias (that duplicate is what made the real
      // bug's GROUP BY ambiguous).
      expect(viewSql).not.toContain('AS user_id');
      expect(viewSql).toContain('LEFT JOIN decrypted_pii d ON s.user_id = d.user_id');
    });

    it('refuses SHADOW_COPY when no declared field has ENCRYPT handling', async () => {
      const registry = new PiiRegistryService([]);
      const service = new SourceRedactionService(
        registry, new BigQuery(), PII_VAULT_RESOURCE_ID, BATCH_DECRYPT_FN
      );
      const resource = makeManualEntry({
        sourceRedactionStrategy: 'SHADOW_COPY',
        piiFields: [
          { name: 'user_id', classification: 'SYSTEM_IDENTIFIER', handling: 'HASH_SURROGATE', requiredInMart: false },
        ],
      });

      await expect(service.ensureShadowCopy(resource)).rejects.toThrow('only ENCRYPT fields are ever synced into pii_vault');
      expect(mockCreateTable).not.toHaveBeenCalled();
    });

    it('omits the tenant filter when the resource has no tenantIdColumn declared', async () => {
      const registry = new PiiRegistryService([]);
      const service = new SourceRedactionService(
        registry, new BigQuery(), PII_VAULT_RESOURCE_ID, BATCH_DECRYPT_FN
      );
      const resource = makeManualEntry({ sourceRedactionStrategy: 'SHADOW_COPY', tenantIdColumn: undefined });

      await service.ensureShadowCopy(resource);

      const [, { view: viewSql }] = mockCreateTable.mock.calls[0] as [string, { view: string }];
      expect(viewSql).not.toContain('WHERE s.');
    });

    it('refuses to build a shadow copy with an unsafe field identifier', async () => {
      const registry = new PiiRegistryService([]);
      const service = new SourceRedactionService(
        registry, new BigQuery(), PII_VAULT_RESOURCE_ID, BATCH_DECRYPT_FN
      );
      const resource = makeManualEntry({
        sourceRedactionStrategy: 'SHADOW_COPY',
        piiFields: [
          { name: 'email); DROP TABLE users; --', classification: 'DIRECT_IDENTIFIER', handling: 'ENCRYPT', requiredInMart: false },
        ],
      });

      await expect(service.ensureShadowCopy(resource)).rejects.toThrow('not a safe column/table name');
      expect(mockCreateTable).not.toHaveBeenCalled();
    });

    it('dropShadowCopyIfExists treats a 404 as a no-op, not an error', async () => {
      deleteTableShouldFail = { code: 404 };
      const registry = new PiiRegistryService([]);
      const service = new SourceRedactionService(registry, new BigQuery());
      const resource = makeManualEntry({ resourceId: 'bigquery:acme-project.crm.contacts' });

      await expect(service.dropShadowCopyIfExists(resource)).resolves.toBeUndefined();
    });

    it('dropShadowCopyIfExists rethrows a real (non-404) failure', async () => {
      deleteTableShouldFail = { code: 500 };
      const registry = new PiiRegistryService([]);
      const service = new SourceRedactionService(registry, new BigQuery());
      const resource = makeManualEntry({ resourceId: 'bigquery:acme-project.crm.contacts' });

      await expect(service.dropShadowCopyIfExists(resource)).rejects.toEqual({ code: 500 });
    });

    it('is a no-op for a non-bigquery resource', async () => {
      const registry = new PiiRegistryService([]);
      const service = new SourceRedactionService(registry, new BigQuery());
      const resource = makeManualEntry({ resourceId: 'salesforce:leads', system: 'salesforce' });

      await service.dropShadowCopyIfExists(resource);

      expect(mockDataset).not.toHaveBeenCalled();
    });
  });
});
