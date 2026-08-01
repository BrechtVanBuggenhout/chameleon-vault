import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import type { PiiRegistryEntry } from '../src/types/pii-registry.js';

const mockGetIamPolicy = jest.fn(async () => [{ bindings: [] }]);
const mockSetIamPolicy = jest.fn(async () => [{}]);
const mockDeleteTable = jest.fn(async () => [{}]);
const mockCreateTable = jest.fn(async () => [{
  getIamPolicy: mockGetIamPolicy,
  setIamPolicy: mockSetIamPolicy,
}]);
const mockTable = jest.fn(() => ({ delete: mockDeleteTable }));
const mockDataset = jest.fn(() => ({ createTable: mockCreateTable, table: mockTable }));

await jest.unstable_mockModule('@google-cloud/bigquery', () => ({
  BigQuery: class {
    dataset = mockDataset;
  },
}));

const { DecryptedViewService } = await import('../src/services/decrypted-view-service.js');
const { PiiRegistryService } = await import('../src/services/pii-registry-service.js');

function makeRepo() {
  const store = new Map<string, any>();
  return {
    create: jest.fn(async (declaration: any) => {
      const record = { ...declaration, status: 'active', created_at: new Date() };
      store.set(`${declaration.tenant_id}:${declaration.view_name}`, record);
      return record;
    }),
    get: jest.fn(async (tenantId: string, viewName: string) => store.get(`${tenantId}:${viewName}`) ?? null),
    revoke: jest.fn(async (tenantId: string, viewName: string, revokedBy: string) => {
      const key = `${tenantId}:${viewName}`;
      const existing = store.get(key);
      if (!existing) return null;
      const revoked = { ...existing, status: 'revoked', revoked_by: revokedBy, revoked_at: new Date() };
      store.set(key, revoked);
      return revoked;
    }),
    listByTenant: jest.fn(async (tenantId: string) =>
      [...store.values()].filter((v) => v.tenant_id === tenantId)
    ),
  };
}

const ENCRYPTED_ENTRY: PiiRegistryEntry = {
  registryVersion: '1',
  resourceId: 'bigquery:proj.ds.raw_users',
  system: 'bigquery',
  piiFields: [
    { name: 'email', classification: 'DIRECT_IDENTIFIER', handling: 'ENCRYPT', requiredInMart: false },
    { name: 'plan', classification: 'BEHAVIORAL', handling: 'REDACT', requiredInMart: false },
  ],
  ownerConnector: 'manual',
  lineageDestination: 'raw_users',
  deletionStrategy: 'CRYPTO_SHRED',
  ghostDataScan: { enabled: false, scanMode: 'DISABLED', patterns: [] },
  handlingPolicy: 'crypto-shred',
  evidencePointers: [],
  tenantId: 'tenant-a',
};

describe('DecryptedViewService', () => {
  let repo: ReturnType<typeof makeRepo>;
  let registry: InstanceType<typeof PiiRegistryService>;
  let service: InstanceType<typeof DecryptedViewService>;

  beforeEach(() => {
    jest.clearAllMocks();
    mockGetIamPolicy.mockResolvedValue([{ bindings: [] }] as any);
    repo = makeRepo();
    registry = new PiiRegistryService([ENCRYPTED_ENTRY]);
    service = new DecryptedViewService(
      'proj',
      'decrypted_views',
      'proj.decrypted_views.chameleon_batch_decrypt',
      repo as any,
      registry
    );
  });

  it('declares a view for a declared, encrypted field: creates the BigQuery view, grants dataViewer, persists the record', async () => {
    const result = await service.declareView({
      tenantId: 'tenant-a',
      viewName: 'campaign_emails',
      sourceResourceId: 'bigquery:proj.ds.raw_users',
      declaredFields: ['email'],
      businessJustification: 'Send campaign confirmations',
      createdBy: 'brecht@chameleon-data.com',
      consumerServiceAccount: 'sender@proj.iam.gserviceaccount.com',
    });

    expect(result.status).toBe('active');
    expect(result.bigquery_view_name).toBe('tenant-a_campaign_emails');

    expect(mockDataset).toHaveBeenCalledWith('decrypted_views');
    expect(mockCreateTable).toHaveBeenCalledWith(
      'tenant-a_campaign_emails',
      expect.objectContaining({ view: expect.stringContaining('chameleon_batch_decrypt(email, user_id, tenant_id)') })
    );
    expect(mockSetIamPolicy).toHaveBeenCalledWith(
      expect.objectContaining({
        bindings: [{ role: 'roles/bigquery.dataViewer', members: ['serviceAccount:sender@proj.iam.gserviceaccount.com'] }],
      })
    );
    expect(repo.create).toHaveBeenCalledTimes(1);
  });

  it('rejects a field that is not declared on the source resource', async () => {
    await expect(
      service.declareView({
        tenantId: 'tenant-a',
        viewName: 'v1',
        sourceResourceId: 'bigquery:proj.ds.raw_users',
        declaredFields: ['phone'],
        businessJustification: 'x',
        createdBy: 'a@b.com',
        consumerServiceAccount: 'sa@proj.iam.gserviceaccount.com',
      })
    ).rejects.toThrow('not declared');
    expect(mockCreateTable).not.toHaveBeenCalled();
  });

  it('rejects a field without a crypto anchor (e.g. REDACT) -- decrypted views only make sense over ENCRYPT/TOKENIZE/HASH_SURROGATE fields', async () => {
    await expect(
      service.declareView({
        tenantId: 'tenant-a',
        viewName: 'v1',
        sourceResourceId: 'bigquery:proj.ds.raw_users',
        declaredFields: ['plan'],
        businessJustification: 'x',
        createdBy: 'a@b.com',
        consumerServiceAccount: 'sa@proj.iam.gserviceaccount.com',
      })
    ).rejects.toThrow('REDACT');
    expect(mockCreateTable).not.toHaveBeenCalled();
  });

  it('rejects an undeclared source resource entirely', async () => {
    await expect(
      service.declareView({
        tenantId: 'tenant-a',
        viewName: 'v1',
        sourceResourceId: 'bigquery:proj.ds.some_undeclared_table',
        declaredFields: ['email'],
        businessJustification: 'x',
        createdBy: 'a@b.com',
        consumerServiceAccount: 'sa@proj.iam.gserviceaccount.com',
      })
    ).rejects.toThrow('No registered PII resource found');
  });

  it('requires a business justification', async () => {
    await expect(
      service.declareView({
        tenantId: 'tenant-a',
        viewName: 'v1',
        sourceResourceId: 'bigquery:proj.ds.raw_users',
        declaredFields: ['email'],
        businessJustification: '   ',
        createdBy: 'a@b.com',
        consumerServiceAccount: 'sa@proj.iam.gserviceaccount.com',
      })
    ).rejects.toThrow('businessJustification is required');
  });

  it('revoking drops the BigQuery view and flips the Firestore record to revoked', async () => {
    await service.declareView({
      tenantId: 'tenant-a',
      viewName: 'campaign_emails',
      sourceResourceId: 'bigquery:proj.ds.raw_users',
      declaredFields: ['email'],
      businessJustification: 'x',
      createdBy: 'a@b.com',
      consumerServiceAccount: 'sa@proj.iam.gserviceaccount.com',
    });

    const revoked = await service.revokeView('tenant-a', 'campaign_emails', 'compliance@chameleon-data.com');

    expect(revoked?.status).toBe('revoked');
    expect(mockTable).toHaveBeenCalledWith('tenant-a_campaign_emails');
    expect(mockDeleteTable).toHaveBeenCalledTimes(1);
  });

  it('revoking a view that was never declared (or already revoked) is a no-op, not an error', async () => {
    const result = await service.revokeView('tenant-a', 'never-existed', 'a@b.com');
    expect(result).toBeNull();
    expect(mockDeleteTable).not.toHaveBeenCalled();
  });
});
