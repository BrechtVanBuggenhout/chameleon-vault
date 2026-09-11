import { describe, it, expect } from '@jest/globals';
import Fastify from 'fastify';
import { healthRoutes } from '../src/routes/health.js';

function buildApp(firestorePing: () => Promise<void>, kmsPing: () => Promise<void>) {
  const app = Fastify();
  return { app, firestore: { ping: firestorePing }, kms: { ping: kmsPing } };
}

describe('GET /health', () => {
  it('returns 200 ok when both dependencies are reachable', async () => {
    const { app, firestore, kms } = buildApp(
      () => Promise.resolve(),
      () => Promise.resolve()
    );
    await app.register(healthRoutes, { firestore, kms });

    const response = await app.inject({ method: 'GET', url: '/health' });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.status).toBe('ok');
    expect(body.dependencies).toEqual({ firestore: { ok: true }, kms: { ok: true } });
  });

  it('returns 503 degraded when Firestore is unreachable, without failing the KMS check', async () => {
    const { app, firestore, kms } = buildApp(
      () => Promise.reject(new Error('DEADLINE_EXCEEDED')),
      () => Promise.resolve()
    );
    await app.register(healthRoutes, { firestore, kms });

    const response = await app.inject({ method: 'GET', url: '/health' });

    expect(response.statusCode).toBe(503);
    const body = response.json();
    expect(body.status).toBe('degraded');
    expect(body.dependencies.firestore).toEqual({ ok: false, error: 'DEADLINE_EXCEEDED' });
    expect(body.dependencies.kms).toEqual({ ok: true });
  });

  it('returns 503 degraded when KMS is unreachable', async () => {
    const { app, firestore, kms } = buildApp(
      () => Promise.resolve(),
      () => Promise.reject(new Error('PERMISSION_DENIED'))
    );
    await app.register(healthRoutes, { firestore, kms });

    const response = await app.inject({ method: 'GET', url: '/health' });

    expect(response.statusCode).toBe(503);
    expect(response.json().dependencies.kms).toEqual({ ok: false, error: 'PERMISSION_DENIED' });
  });

  it('treats a hanging dependency as unhealthy rather than hanging the request', async () => {
    const { app, firestore, kms } = buildApp(
      () => new Promise(() => {}), // never resolves
      () => Promise.resolve()
    );
    await app.register(healthRoutes, { firestore, kms });

    const response = await app.inject({ method: 'GET', url: '/health' });

    expect(response.statusCode).toBe(503);
    expect(response.json().dependencies.firestore.ok).toBe(false);
  }, 10_000);
});
