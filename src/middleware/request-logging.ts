import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { createLogger } from '../logging/index.js';
import { randomUUID } from 'crypto';

const logger = createLogger('request-logging');

export interface RequestContext {
  correlationId: string;
  userId?: string;
  tenantId?: string;
  operation?: string;
  startTime: number;
  operationId?: string;
  deletionRequestId?: string;
  // Set by main.ts's auth hook when the caller authenticated with a
  // per-analyst credential rather than the shared VAULT_API_KEY -- lets
  // /encrypt and /decrypt attribute their audit events to a specific person.
  analystEmail?: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    requestContext?: RequestContext;
  }
}

export function getRequestContext(request: FastifyRequest): RequestContext {
  if (!request.requestContext) {
    request.requestContext = {
      correlationId: randomUUID(),
      startTime: Date.now(),
    };
  }

  return request.requestContext;
}

export async function registerRequestLogging(fastify: FastifyInstance) {
  fastify.addHook('preHandler', async (request: FastifyRequest, _reply: FastifyReply) => {
    const correlationId = request.headers['x-correlation-id'] || randomUUID();
    const startTime = Date.now();

    const context: RequestContext = {
      correlationId: correlationId as string,
      startTime,
    };

    request.requestContext = context;

    logger.debug(
      {
        correlationId,
        method: request.method,
        url: request.url,
        ip: request.ip,
      },
      'Incoming request'
    );
  });

  fastify.addHook('onResponse', async (request: FastifyRequest, reply: FastifyReply) => {
    const context = request.requestContext;
    if (!context) {
      return;
    }

    const duration = Date.now() - context.startTime;

    const level = reply.statusCode >= 400 ? 'warn' : 'info';
    logger[level](
      {
        correlationId: context.correlationId,
        method: request.method,
        url: request.url,
        statusCode: reply.statusCode,
        durationMs: duration,
        operation: context.operation,
      },
      `${request.method} ${request.url} completed`
    );
  });
}
