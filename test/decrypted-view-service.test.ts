import { jest, describe, it, expect, beforeEach } from '@jest/globals';

const mockGetIamPolicy = jest.fn(async () => [{ bindings: [] }]);
const mockSetIamPolicy = jest.fn(async () => [{}]);
const mockDeleteTable = jest.fn(async () => [{}]);
const mockCreateTable = jest.fn(async () => [{
  getIamPolicy: mockGetIamPolicy,
  setIamPolicy: mockSetIamPolicy,
}]);
const mockTable = jest.fn(() => ({ delete: mockDeleteTable }));
const mockDataset = jest.fn(() => ({ createTable: mockCreateTable, table: mockTable }));

// Field names with at least one synced row in pii_vault for the tenant --
// what SELECT DISTINCT field_name ... WHERE tenant_id = @tenantId would
// return. declareView() and the available-fields route both go through
// getAvailableFields(), so this one mock covers both.
let availableFieldRows: { field_name: string }[] = [{ field_name: 'email' }];
const mockQuery = jest.fn(async () => [availableFieldRows]);

await jest.unstable_mockModule('@google-cloud/bigquery', () => ({
  BigQuery: class {
    dataset = mockDataset;
    query = mockQuery;
  },
}));

const { DecryptedViewService } = await import('../src/services/decrypted-view-service.js');

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

describe('DecryptedViewService', () => {
  let repo: ReturnType<typeof makeRepo>;
  let service: InstanceType<typeof DecryptedViewService>;

  beforeEach(() => {
    jest.clearAllMocks();
    mockGetIamPolicy.mockResolvedValue([{ bindings: [] }] as any);
    availableFieldRows = [{ field_name: 'email' }];
    repo = makeRepo();
    service = new DecryptedViewService(
      'my-proj-123',
      'decrypted_views',
      'my-proj-123.decrypted_views.chameleon_batch_decrypt',
      'bigquery:my-proj-123.ds.pii_vault',
      repo as any
    );
  });

  it('declares a view for a field synced into pii_vault: creates the BigQuery view, grants dataViewer, persists the record', async () => {
    const result = await service.declareView({
      tenantId: 'tenant-a',
      viewName: 'campaign_emails',
      declaredFields: ['email'],
      businessJustification: 'Send campaign confirmations',
      createdBy: 'brecht@chameleon-data.com',
      consumerServiceAccount: 'sender@proj.iam.gserviceaccount.com',
    });

    expect(result.status).toBe('active');
    expect(result.bigquery_view_name).toBe('tenant-a_campaign_emails');
    // Always the central pii_vault table -- never a customer-supplied source.
    expect(result.source_resource_id).toBe('bigquery:my-proj-123.ds.pii_vault');

    expect(mockDataset).toHaveBeenCalledWith('decrypted_views');
    expect(mockCreateTable).toHaveBeenCalledWith(
      'tenant-a_campaign_emails',
      expect.objectContaining({
        // pii_vault is long-format (one row per user+field), so each
        // declared field is pivoted out by field_name, decrypting only
        // encrypted_value (never the non-reversible token column), scoped
        // to the declaring tenant.
        // The function ref is backtick-quoted in the generated SQL --
        // project IDs routinely contain hyphens (e.g. "my-proj-123"), and
        // BigQuery parses an unquoted hyphenated path as subtraction, not
        // an identifier, breaking the CREATE VIEW statement outright.
        view: expect.stringMatching(
          /IF\(field_name = 'email', `my-proj-123\.decrypted_views\.chameleon_batch_decrypt`\(CAST\(encrypted_value AS STRING\), user_id, tenant_id\), NULL\)/
        ),
      })
    );
    expect(mockCreateTable).toHaveBeenCalledWith(
      'tenant-a_campaign_emails',
      expect.objectContaining({ view: expect.stringContaining("WHERE tenant_id = 'tenant-a'") })
    );
    expect(mockSetIamPolicy).toHaveBeenCalledWith(
      expect.objectContaining({
        bindings: [{ role: 'roles/bigquery.dataViewer', members: ['serviceAccount:sender@proj.iam.gserviceaccount.com'] }],
      })
    );
    expect(repo.create).toHaveBeenCalledTimes(1);
  });

  it('rejects a field with no synced rows in pii_vault for the tenant', async () => {
    availableFieldRows = [{ field_name: 'email' }]; // no 'phone'
    await expect(
      service.declareView({
        tenantId: 'tenant-a',
        viewName: 'v1',
        declaredFields: ['phone'],
        businessJustification: 'x',
        createdBy: 'a@b.com',
        consumerServiceAccount: 'sa@proj.iam.gserviceaccount.com',
      })
    ).rejects.toThrow('no synced rows in pii_vault');
    expect(mockCreateTable).not.toHaveBeenCalled();
  });

  it('requires a business justification', async () => {
    await expect(
      service.declareView({
        tenantId: 'tenant-a',
        viewName: 'v1',
        declaredFields: ['email'],
        businessJustification: '   ',
        createdBy: 'a@b.com',
        consumerServiceAccount: 'sa@proj.iam.gserviceaccount.com',
      })
    ).rejects.toThrow('businessJustification is required');
  });

  it('requires at least one declared field', async () => {
    await expect(
      service.declareView({
        tenantId: 'tenant-a',
        viewName: 'v1',
        declaredFields: [],
        businessJustification: 'x',
        createdBy: 'a@b.com',
        consumerServiceAccount: 'sa@proj.iam.gserviceaccount.com',
      })
    ).rejects.toThrow('At least one declared field');
  });

  it('getAvailableFields returns the distinct field names synced for a tenant', async () => {
    availableFieldRows = [{ field_name: 'email' }, { field_name: 'phone' }];
    const fields = await service.getAvailableFields('tenant-a');
    expect(fields).toEqual(['email', 'phone']);
    expect(mockQuery).toHaveBeenCalledWith(
      expect.objectContaining({ params: { tenantId: 'tenant-a' } })
    );
  });

  it('revoking drops the BigQuery view and flips the Firestore record to revoked', async () => {
    await service.declareView({
      tenantId: 'tenant-a',
      viewName: 'campaign_emails',
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

  describe('getDistinctSyncedTenantIds', () => {
    it('returns the distinct tenant_id values actually present in pii_vault', async () => {
      mockQuery.mockResolvedValueOnce([[{ tenant_id: 'immoscoop-prod' }, { tenant_id: 'acme' }]] as any);

      const tenantIds = await service.getDistinctSyncedTenantIds();

      expect(tenantIds).toEqual(['immoscoop-prod', 'acme']);
      expect(mockQuery).toHaveBeenCalledWith(
        expect.objectContaining({ params: { limit: 5 } })
      );
    });

    it('respects a custom limit', async () => {
      mockQuery.mockResolvedValueOnce([[{ tenant_id: 'a' }]] as any);
      await service.getDistinctSyncedTenantIds(1);
      expect(mockQuery).toHaveBeenCalledWith(expect.objectContaining({ params: { limit: 1 } }));
    });
  });
});
