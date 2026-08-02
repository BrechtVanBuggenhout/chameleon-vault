import { jest, describe, it, expect, beforeEach } from '@jest/globals';

const { default: Fastify } = await import('fastify');
const { decryptedViewsRoutes } = await import('../src/routes/decrypted-views.js');

function makeFakes() {
  const declareView = jest.fn();
  const revokeView = jest.fn();
  const getAvailableFields = jest.fn();
  const listByTenant = jest.fn();
  return {
    decryptedViewService: { declareView, revokeView, getAvailableFields } as any,
    decryptedViewsRepository: { listByTenant } as any,
    declareView,
    revokeView,
    getAvailableFields,
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
});
