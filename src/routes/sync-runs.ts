import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { createLogger } from '../logging/index.js';
import type { SyncRunRepository } from '../gcp/sync-run-repository.js';

const logger = createLogger('sync-runs-routes');

export interface SyncRunsRoutesOptions {
  syncRunRepository: SyncRunRepository;
  /** Same shared secret as pii-registry's mark-synced route -- worker-only writes. */
  writeToken?: string;
}

/**
 * Backs the console's sync progress bar. Created and updated exclusively by
 * chameleon-data-pipelines' PiiVaultSyncJob (POST routes, worker-auth
 * gated); polled by the console (GET, open to any authenticated caller,
 * same as the rest of the registry read surface).
 */
export async function syncRunsRoutes(fastify: FastifyInstance, options: SyncRunsRoutesOptions): Promise<void> {
  const { syncRunRepository, writeToken } = options;

  const requireWriteAuth = async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (!writeToken) {
      reply.status(503).send({ error: 'Sync run write API is not enabled', statusCode: 503 });
      return;
    }
    const header = request.headers.authorization ?? '';
    const provided = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : '';
    if (provided !== writeToken) {
      reply.status(401).send({ error: 'Unauthorized', statusCode: 401 });
      return;
    }
  };

  fastify.post('/pii-registry/sync-runs', { preHandler: requireWriteAuth }, async (request, reply) => {
    const { runId, tenantId, resourceId } = (request.body ?? {}) as {
      runId?: string;
      tenantId?: string;
      resourceId?: string;
    };
    if (!runId || !tenantId) {
      return reply.status(400).send({ error: 'runId and tenantId are required', statusCode: 400 });
    }

    try {
      const run = await syncRunRepository.create({ runId, tenantId, resourceId });
      return reply.status(201).send({ run, timestamp: new Date().toISOString() });
    } catch (error) {
      logger.error({ error, runId }, 'Failed to create sync run');
      return reply.status(500).send({ error: 'Failed to create sync run', statusCode: 500 });
    }
  });

  fastify.post(
    '/pii-registry/sync-runs/:runId/finalize-total',
    { preHandler: requireWriteAuth },
    async (request, reply) => {
      const { runId } = request.params as { runId: string };
      const { chunksTotal } = (request.body ?? {}) as { chunksTotal?: number };
      if (typeof chunksTotal !== 'number' || chunksTotal < 0) {
        return reply.status(400).send({ error: 'chunksTotal must be a non-negative number', statusCode: 400 });
      }

      try {
        const run = await syncRunRepository.finalizeTotal(runId, chunksTotal);
        if (!run) {
          return reply.status(404).send({ error: 'Sync run not found', statusCode: 404 });
        }
        return reply.send({ run, timestamp: new Date().toISOString() });
      } catch (error) {
        logger.error({ error, runId }, 'Failed to finalize sync run total');
        return reply.status(500).send({ error: 'Failed to finalize sync run total', statusCode: 500 });
      }
    }
  );

  fastify.post('/pii-registry/sync-runs/:runId/progress', { preHandler: requireWriteAuth }, async (request, reply) => {
    const { runId } = request.params as { runId: string };
    const { outcome } = (request.body ?? {}) as { outcome?: string };
    if (outcome !== 'completed' && outcome !== 'failed') {
      return reply.status(400).send({ error: "outcome must be 'completed' or 'failed'", statusCode: 400 });
    }

    try {
      const run = await syncRunRepository.recordChunkOutcome(runId, outcome);
      if (!run) {
        // Best-effort by design (see SyncRunRepository.recordChunkOutcome) --
        // a missing run doc is a reporting gap, not the caller's fault; the
        // caller (process_chunk) must never fail the actual sync over this.
        return reply.status(200).send({ recorded: false, timestamp: new Date().toISOString() });
      }
      return reply.send({ run, timestamp: new Date().toISOString() });
    } catch (error) {
      logger.error({ error, runId }, 'Failed to record sync chunk outcome');
      return reply.status(500).send({ error: 'Failed to record sync chunk outcome', statusCode: 500 });
    }
  });

  fastify.get('/pii-registry/sync-runs/:runId', async (request, reply) => {
    const { runId } = request.params as { runId: string };
    try {
      const run = await syncRunRepository.get(runId);
      if (!run) {
        return reply.status(404).send({ error: 'Sync run not found', statusCode: 404 });
      }
      return reply.send({ run, timestamp: new Date().toISOString() });
    } catch (error) {
      logger.error({ error, runId }, 'Failed to fetch sync run');
      return reply.status(500).send({ error: 'Failed to fetch sync run', statusCode: 500 });
    }
  });
}
