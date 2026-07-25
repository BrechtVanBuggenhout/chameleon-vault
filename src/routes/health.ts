import { FastifyInstance } from 'fastify';

export async function healthRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.get('/health', async (request, reply) => {
    return reply.send({
      status: 'ok',
      timestamp: new Date().toISOString(),
      service: 'chameleon-key-vault',
      version: '0.1.0',
    });
  });

  fastify.get('/ready', async (request, reply) => {
    // TODO: Check GCP service connectivity
    return reply.send({
      ready: true,
      timestamp: new Date().toISOString(),
    });
  });
}
