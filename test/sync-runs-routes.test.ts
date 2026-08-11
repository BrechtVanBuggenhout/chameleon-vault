import { describe, expect, it, jest, beforeEach } from '@jest/globals';
import Fastify from 'fastify';
import { syncRunsRoutes } from '../src/routes/sync-runs.js';
import type { SyncRun } from '../src/types/sync-run.js';

const WRITE_TOKEN = 'test-write-token';

function makeFakeRepo() {
  const create = jest.fn<(input: { runId: string; tenantId: string; resourceId?: string }) => Promise<SyncRun>>();
  const get = jest.fn<(runId: string) => Promise<SyncRun | null>>();
  const finalizeTotal = jest.fn<(runId: string, chunksTotal: number) => Promise<SyncRun | null>>();
  const recordChunkOutcome = jest.fn<(runId: string, outcome: 'completed' | 'failed') => Promise<SyncRun | null>>();
  return { create, get, finalizeTotal, recordChunkOutcome };
}

function baseRun(overrides: Partial<SyncRun> = {}): SyncRun {
  return {
    runId: 'run-1',
    tenantId: 'default-tenant',
    status: 'enumerating',
    chunksTotal: null,
    chunksCompleted: 0,
    chunksFailed: 0,
    startedAt: '2026-08-11T00:00:00.000Z',
    ...overrides,
  };
}

describe('syncRunsRoutes', () => {
  let repo: ReturnType<typeof makeFakeRepo>;
  let app: ReturnType<typeof Fastify>;

  beforeEach(async () => {
    repo = makeFakeRepo();
    app = Fastify({ logger: false });
    await app.register(syncRunsRoutes, { syncRunRepository: repo as any, writeToken: WRITE_TOKEN });
  });

  describe('POST /pii-registry/sync-runs', () => {
    it('creates a run and returns 201 with a valid write token', async () => {
      const run = baseRun();
      repo.create.mockResolvedValue(run);

      const response = await app.inject({
        method: 'POST',
        url: '/pii-registry/sync-runs',
        headers: { authorization: `Bearer ${WRITE_TOKEN}` },
        payload: { runId: 'run-1', tenantId: 'default-tenant' },
      });

      expect(response.statusCode).toBe(201);
      expect(repo.create).toHaveBeenCalledWith({ runId: 'run-1', tenantId: 'default-tenant', resourceId: undefined });
      expect(JSON.parse(response.body).run).toEqual(run);
    });

    it('rejects without a valid write token', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/pii-registry/sync-runs',
        payload: { runId: 'run-1', tenantId: 'default-tenant' },
      });

      expect(response.statusCode).toBe(401);
      expect(repo.create).not.toHaveBeenCalled();
    });

    it('returns 400 when runId or tenantId is missing', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/pii-registry/sync-runs',
        headers: { authorization: `Bearer ${WRITE_TOKEN}` },
        payload: { runId: 'run-1' },
      });

      expect(response.statusCode).toBe(400);
      expect(repo.create).not.toHaveBeenCalled();
    });
  });

  describe('POST /pii-registry/sync-runs/:runId/finalize-total', () => {
    it('finalizes the total and returns the updated run', async () => {
      const run = baseRun({ status: 'running', chunksTotal: 12 });
      repo.finalizeTotal.mockResolvedValue(run);

      const response = await app.inject({
        method: 'POST',
        url: '/pii-registry/sync-runs/run-1/finalize-total',
        headers: { authorization: `Bearer ${WRITE_TOKEN}` },
        payload: { chunksTotal: 12 },
      });

      expect(response.statusCode).toBe(200);
      expect(repo.finalizeTotal).toHaveBeenCalledWith('run-1', 12);
      expect(JSON.parse(response.body).run).toEqual(run);
    });

    it('returns 404 when the run does not exist', async () => {
      repo.finalizeTotal.mockResolvedValue(null);

      const response = await app.inject({
        method: 'POST',
        url: '/pii-registry/sync-runs/missing/finalize-total',
        headers: { authorization: `Bearer ${WRITE_TOKEN}` },
        payload: { chunksTotal: 5 },
      });

      expect(response.statusCode).toBe(404);
    });

    it('returns 400 when chunksTotal is not a valid number', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/pii-registry/sync-runs/run-1/finalize-total',
        headers: { authorization: `Bearer ${WRITE_TOKEN}` },
        payload: {},
      });

      expect(response.statusCode).toBe(400);
      expect(repo.finalizeTotal).not.toHaveBeenCalled();
    });
  });

  describe('POST /pii-registry/sync-runs/:runId/progress', () => {
    it('records a completed chunk outcome', async () => {
      const run = baseRun({ status: 'running', chunksTotal: 12, chunksCompleted: 1 });
      repo.recordChunkOutcome.mockResolvedValue(run);

      const response = await app.inject({
        method: 'POST',
        url: '/pii-registry/sync-runs/run-1/progress',
        headers: { authorization: `Bearer ${WRITE_TOKEN}` },
        payload: { outcome: 'completed' },
      });

      expect(response.statusCode).toBe(200);
      expect(repo.recordChunkOutcome).toHaveBeenCalledWith('run-1', 'completed');
      expect(JSON.parse(response.body).run).toEqual(run);
    });

    it('returns 200 with recorded:false (never fails the caller) when the run is missing', async () => {
      repo.recordChunkOutcome.mockResolvedValue(null);

      const response = await app.inject({
        method: 'POST',
        url: '/pii-registry/sync-runs/missing/progress',
        headers: { authorization: `Bearer ${WRITE_TOKEN}` },
        payload: { outcome: 'completed' },
      });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).recorded).toBe(false);
    });

    it('returns 400 for an invalid outcome value', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/pii-registry/sync-runs/run-1/progress',
        headers: { authorization: `Bearer ${WRITE_TOKEN}` },
        payload: { outcome: 'bogus' },
      });

      expect(response.statusCode).toBe(400);
      expect(repo.recordChunkOutcome).not.toHaveBeenCalled();
    });
  });

  describe('GET /pii-registry/sync-runs/:runId', () => {
    it('returns the run without requiring a write token', async () => {
      const run = baseRun({ status: 'complete', chunksTotal: 3, chunksCompleted: 3 });
      repo.get.mockResolvedValue(run);

      const response = await app.inject({ method: 'GET', url: '/pii-registry/sync-runs/run-1' });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).run).toEqual(run);
    });

    it('returns 404 when the run does not exist', async () => {
      repo.get.mockResolvedValue(null);

      const response = await app.inject({ method: 'GET', url: '/pii-registry/sync-runs/missing' });

      expect(response.statusCode).toBe(404);
    });
  });

  it('disables writes with 503 when no write token is configured', async () => {
    const unauthedApp = Fastify({ logger: false });
    await unauthedApp.register(syncRunsRoutes, { syncRunRepository: repo as any });

    const response = await unauthedApp.inject({
      method: 'POST',
      url: '/pii-registry/sync-runs',
      payload: { runId: 'run-1', tenantId: 'default-tenant' },
    });

    expect(response.statusCode).toBe(503);
    await unauthedApp.close();
  });
});
