import { describe, expect, it, jest } from '@jest/globals';
import Fastify from 'fastify';
import { adminServiceCredentialsRoutes } from '../src/routes/admin-service-credentials.js';
import type { AnalystAccessService } from '../src/services/analyst-access-service.js';

describe('adminServiceCredentialsRoutes', () => {
  describe('POST /admin/service-credentials', () => {
    it('mints a service credential for a valid callerName', async () => {
      const mintServiceCredential = jest.fn().mockResolvedValue({ credential: 'raw-service-credential-value' });
      const app = Fastify({ logger: false });
      await app.register(adminServiceCredentialsRoutes, {
        analystAccessService: { mintServiceCredential } as unknown as AnalystAccessService,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/admin/service-credentials',
        headers: { 'x-tenant-id': 'acme' },
        payload: { callerName: 'partner:acme-crm' },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.credential).toBe('raw-service-credential-value');
      expect(body.tenantId).toBe('acme');
      expect(body.callerName).toBe('partner:acme-crm');
      expect(mintServiceCredential).toHaveBeenCalledWith('acme', 'partner:acme-crm');

      await app.close();
    });

    it('defaults to default-tenant when no x-tenant-id header is sent', async () => {
      const mintServiceCredential = jest.fn().mockResolvedValue({ credential: 'raw-value' });
      const app = Fastify({ logger: false });
      await app.register(adminServiceCredentialsRoutes, {
        analystAccessService: { mintServiceCredential } as unknown as AnalystAccessService,
      });

      await app.inject({
        method: 'POST',
        url: '/admin/service-credentials',
        payload: { callerName: 'partner:acme-crm' },
      });

      expect(mintServiceCredential).toHaveBeenCalledWith('default-tenant', 'partner:acme-crm');
      await app.close();
    });

    it('rejects a missing callerName with 400', async () => {
      const mintServiceCredential = jest.fn();
      const app = Fastify({ logger: false });
      await app.register(adminServiceCredentialsRoutes, {
        analystAccessService: { mintServiceCredential } as unknown as AnalystAccessService,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/admin/service-credentials',
        payload: {},
      });

      expect(res.statusCode).toBe(400);
      expect(mintServiceCredential).not.toHaveBeenCalled();

      await app.close();
    });
  });

  describe('POST /admin/service-credentials/revoke', () => {
    it('revokes every credential matching (tenantId, callerName) and reports how many', async () => {
      const revokeServiceCredentials = jest.fn().mockResolvedValue(2);
      const app = Fastify({ logger: false });
      await app.register(adminServiceCredentialsRoutes, {
        analystAccessService: { revokeServiceCredentials } as unknown as AnalystAccessService,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/admin/service-credentials/revoke',
        headers: { 'x-tenant-id': 'acme' },
        payload: { callerName: 'partner:acme-crm' },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.revokedCount).toBe(2);
      expect(revokeServiceCredentials).toHaveBeenCalledWith('acme', 'partner:acme-crm');

      await app.close();
    });

    it('reports revokedCount 0, not an error, when nothing matches', async () => {
      const revokeServiceCredentials = jest.fn().mockResolvedValue(0);
      const app = Fastify({ logger: false });
      await app.register(adminServiceCredentialsRoutes, {
        analystAccessService: { revokeServiceCredentials } as unknown as AnalystAccessService,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/admin/service-credentials/revoke',
        payload: { callerName: 'never-provisioned' },
      });

      expect(res.statusCode).toBe(200);
      expect(JSON.parse(res.body).revokedCount).toBe(0);

      await app.close();
    });

    it('rejects a missing callerName with 400', async () => {
      const revokeServiceCredentials = jest.fn();
      const app = Fastify({ logger: false });
      await app.register(adminServiceCredentialsRoutes, {
        analystAccessService: { revokeServiceCredentials } as unknown as AnalystAccessService,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/admin/service-credentials/revoke',
        payload: {},
      });

      expect(res.statusCode).toBe(400);
      expect(revokeServiceCredentials).not.toHaveBeenCalled();

      await app.close();
    });
  });
});
