import { FastifyInstance } from 'fastify';

export async function healthRoutes(fastify: FastifyInstance): Promise<void> {
  // logLevel: 'silent' -- these are hit continuously by Cloud Run's own
  // health probes, not real traffic; without this every probe logs an
  // "incoming request"/"request completed" pair that drowns out real
  // request logs in prod.
  fastify.get('/health', { logLevel: 'silent' }, async (request, reply) => {
    return reply.send({
      status: 'ok',
      timestamp: new Date().toISOString(),
      service: 'chameleon-key-vault',
      version: '0.1.0',
    });
  });

  fastify.get('/ready', { logLevel: 'silent' }, async (request, reply) => {
    // TODO: Check GCP service connectivity
    return reply.send({
      ready: true,
      timestamp: new Date().toISOString(),
    });
  });
}
