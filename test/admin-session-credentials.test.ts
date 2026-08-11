import { describe, expect, it, jest } from '@jest/globals';
import Fastify from 'fastify';
import { adminSessionCredentialsRoutes } from '../src/routes/admin-session-credentials.js';
import type { AnalystAccessService } from '../src/services/analyst-access-service.js';

describe('adminSessionCredentialsRoutes', () => {
  it('mints a session credential for a valid email', async () => {
    const mintSessionCredential = jest
      .fn()
      .mockResolvedValue({ credential: 'raw-credential-value', expiresAt: new Date('2026-08-10T01:00:00.000Z') });
    const app = Fastify({ logger: false });
    await app.register(adminSessionCredentialsRoutes, {
      analystAccessService: { mintSessionCredential } as unknown as AnalystAccessService,
    });

    const res = await app.inject({
      method: 'POST',
      url: '/admin/session-credentials',
      headers: { 'x-tenant-id': 'acme' },
      payload: { email: 'person@example.com' },
    });

    expect(res.statusCode).toBe(201);
    const body = JSON.parse(res.body);
    expect(body.credential).toBe('raw-credential-value');
    expect(body.expiresAt).toBe('2026-08-10T01:00:00.000Z');
    expect(mintSessionCredential).toHaveBeenCalledWith('acme', 'person@example.com');

    await app.close();
  });

  it('rejects a missing or invalid email with 400', async () => {
    const mintSessionCredential = jest.fn();
    const app = Fastify({ logger: false });
    await app.register(adminSessionCredentialsRoutes, {
      analystAccessService: { mintSessionCredential } as unknown as AnalystAccessService,
    });

    const res = await app.inject({
      method: 'POST',
      url: '/admin/session-credentials',
      payload: { email: 'not-an-email' },
    });

    expect(res.statusCode).toBe(400);
    expect(mintSessionCredential).not.toHaveBeenCalled();

    await app.close();
  });
});
