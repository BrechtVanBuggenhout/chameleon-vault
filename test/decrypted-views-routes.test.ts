import { jest, describe, it, expect, beforeEach } from '@jest/globals';

const { default: Fastify } = await import('fastify');
const { decryptedViewsRoutes } = await import('../src/routes/decrypted-views.js');

function makeFakes() {
  const declareView = jest.fn();
  const revokeView = jest.fn();
  const getAvailableFields = jest.fn();
  const getDistinctSyncedTenantIds = jest.fn().mockResolvedValue([]);
  const listByTenant = jest.fn();
  return {
    decryptedViewService: { declareView, revokeView, getAvailableFields, getDistinctSyncedTenantIds } as any,
    decryptedViewsRepository: { listByTenant } as any,
    declareView,
    revokeView,
    getAvailableFields,
    getDistinctSyncedTenantIds,
    listByTenant,
  };
}

describe('Decrypted Views management routes', () => {
  let fakes: ReturnType<typeof makeFakes>;
  let app: ReturnType<typeof Fastify>;

  beforeEach(async () => {
    fakes = makeFakes();
    app = Fastify();
    await app.register(decryptedViewsRoutes, {
      decryptedViewService: fakes.decryptedViewService,
      decryptedViewsRepository: fakes.decryptedViewsRepository,
    });
  });

  it('POST /decrypted-views returns 201 with the declared view on success', async () => {
    fakes.declareView.mockResolvedValue({ tenant_id: 't1', view_name: 'v1', status: 'active' });

    const response = await app.inject({
      method: 'POST',
      url: '/decrypted-views',
      headers: { 'x-tenant-id': 't1' },
      payload: {
        viewName: 'v1',
        declaredFields: ['email'],
        businessJustification: 'send receipts',
        createdBy: 'a@b.com',
        consumerServiceAccount: 'sa@p.iam.gserviceaccount.com',
      },
    });

    expect(response.statusCode).toBe(201);
    expect(fakes.declareView).toHaveBeenCalledWith(expect.objectContaining({ tenantId: 't1', viewName: 'v1' }));
  });

  it('POST /decrypted-views returns 400 with the service error message on validation failure', async () => {
    fakes.declareView.mockRejectedValue(new Error('businessJustification is required.'));

    const response = await app.inject({
      method: 'POST',
      url: '/decrypted-views',
      payload: { viewName: 'v1' },
    });

    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.body).message).toContain('businessJustification is required');
  });

  it('GET /decrypted-views lists declarations scoped to the requesting tenant', async () => {
    fakes.listByTenant.mockResolvedValue([{ view_name: 'v1' }]);

    const response = await app.inject({ method: 'GET', url: '/decrypted-views', headers: { 'x-tenant-id': 't1' } });

    expect(response.statusCode).toBe(200);
    expect(fakes.listByTenant).toHaveBeenCalledWith('t1');
    expect(JSON.parse(response.body).views).toEqual([{ view_name: 'v1' }]);
  });

  it('DELETE /decrypted-views/:viewName returns 404 when nothing to revoke', async () => {
    fakes.revokeView.mockResolvedValue(null);

    const response = await app.inject({ method: 'DELETE', url: '/decrypted-views/nope', payload: {} });

    expect(response.statusCode).toBe(404);
  });

  it('DELETE /decrypted-views/:viewName returns the revoked record on success', async () => {
    fakes.revokeView.mockResolvedValue({ view_name: 'v1', status: 'revoked' });

    const response = await app.inject({
      method: 'DELETE',
      url: '/decrypted-views/v1',
      payload: { revokedBy: 'compliance@chameleon-data.com' },
    });

    expect(response.statusCode).toBe(200);
    expect(fakes.revokeView).toHaveBeenCalledWith('default-tenant', 'v1', 'compliance@chameleon-data.com');
  });

  it('GET /decrypted-views/available-fields returns field names synced into pii_vault for the tenant', async () => {
    fakes.getAvailableFields.mockResolvedValue(['email', 'phone']);

    const response = await app.inject({
      method: 'GET',
      url: '/decrypted-views/available-fields',
      headers: { 'x-tenant-id': 't1' },
    });

    expect(response.statusCode).toBe(200);
    expect(fakes.getAvailableFields).toHaveBeenCalledWith('t1');
    expect(JSON.parse(response.body).fields).toEqual(['email', 'phone']);
  });

  it('GET /decrypted-views/available-fields returns 500 with a message on failure, not a bare crash', async () => {
    fakes.getAvailableFields.mockRejectedValue(new Error('BigQuery unavailable'));

    const response = await app.inject({ method: 'GET', url: '/decrypted-views/available-fields' });

    expect(response.statusCode).toBe(500);
    expect(JSON.parse(response.body).message).toContain('BigQuery unavailable');
  });

  it('GET /decrypted-views/available-fields does not check for a tenant mismatch when fields were actually found', async () => {
    fakes.getAvailableFields.mockResolvedValue(['email']);

    const response = await app.inject({
      method: 'GET',
      url: '/decrypted-views/available-fields',
      headers: { 'x-tenant-id': 't1' },
    });

    expect(response.statusCode).toBe(200);
    expect(fakes.getDistinctSyncedTenantIds).not.toHaveBeenCalled();
  });

  it('GET /decrypted-views/available-fields surfaces other tenant_ids with real data when this tenant has none', async () => {
    fakes.getAvailableFields.mockResolvedValue([]);
    fakes.getDistinctSyncedTenantIds.mockResolvedValue(['immoscoop-prod', 'default-tenant']);

    const response = await app.inject({
      method: 'GET',
      url: '/decrypted-views/available-fields',
      headers: { 'x-tenant-id': 'default-tenant' },
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.fields).toEqual([]);
    // Own tenant filtered out even though the fake returned it -- only a
    // genuinely different tenant_id is a useful diagnostic.
    expect(body.otherTenantIdsWithData).toEqual(['immoscoop-prod']);
  });

  it('GET /decrypted-views/available-fields omits otherTenantIdsWithData entirely when nothing has synced anywhere', async () => {
    fakes.getAvailableFields.mockResolvedValue([]);
    fakes.getDistinctSyncedTenantIds.mockResolvedValue([]);

    const response = await app.inject({ method: 'GET', url: '/decrypted-views/available-fields' });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.fields).toEqual([]);
    expect(body).not.toHaveProperty('otherTenantIdsWithData');
  });

  it('GET /decrypted-views/available-fields still returns 200 with an empty result if the diagnostic query itself fails', async () => {
    fakes.getAvailableFields.mockResolvedValue([]);
    fakes.getDistinctSyncedTenantIds.mockRejectedValue(new Error('BigQuery unavailable'));

    const response = await app.inject({ method: 'GET', url: '/decrypted-views/available-fields' });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body).fields).toEqual([]);
  });
});
