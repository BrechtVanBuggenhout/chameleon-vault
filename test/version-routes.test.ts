import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import Fastify from 'fastify';
import { versionRoutes } from '../src/routes/version.js';

const mockCheck = jest.fn();
const fakeSourceStalenessChecker = { check: mockCheck } as any;

function buildApp() {
  return Fastify();
}

describe('GET /version/source-staleness', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns not_applicable when no PII Ingestor Worker is configured', async () => {
    const app = buildApp();
    await app.register(versionRoutes, {});

    const response = await app.inject({ method: 'GET', url: '/version/source-staleness' });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: 'not_applicable', reason: 'PII Ingestor Worker not configured' });
  });

  it('proxies the checker result when configured', async () => {
    mockCheck.mockResolvedValueOnce({
      status: 'ok',
      results: { 'key-vault': { status: 'stale', builtSha: 'a', latestSha: 'b' } },
    });
    const app = buildApp();
    await app.register(versionRoutes, { sourceStalenessChecker: fakeSourceStalenessChecker });

    const response = await app.inject({ method: 'GET', url: '/version/source-staleness' });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      status: 'ok',
      results: { 'key-vault': { status: 'stale', builtSha: 'a', latestSha: 'b' } },
    });
  });

  it('returns 502 rather than crashing when the worker is unreachable', async () => {
    mockCheck.mockRejectedValueOnce(new Error('503: worker down'));
    const app = buildApp();
    await app.register(versionRoutes, { sourceStalenessChecker: fakeSourceStalenessChecker });

    const response = await app.inject({ method: 'GET', url: '/version/source-staleness' });

    expect(response.statusCode).toBe(502);
    expect(response.json()).toEqual({ status: 'error', reason: 'Failed to reach the PII Ingestor Worker' });
  });
});
