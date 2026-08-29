import { FastifyInstance } from 'fastify';
import { AnalystAccessService } from '../services/analyst-access-service.js';
import { createLogger } from '../logging/index.js';
import { getRequestContext } from '../middleware/request-logging.js';
import {
  validateRequest,
  createAnalystClaimsSchema,
  createAuditorClaimsSchema,
  claimAnalystTokenSchema,
} from '../middleware/validation.js';

const logger = createLogger('analyst-claims-routes');

export interface AnalystClaimsRoutesOptions {
  analystAccessService: AnalystAccessService;
}

export async function analystClaimsRoutes(fastify: FastifyInstance, options: AnalystClaimsRoutesOptions): Promise<void> {
  const { analystAccessService } = options;

  /**
   * POST /admin/analyst-claims
   * Creates one one-time claim token per analyst email. Gated by the
   * standard shared-secret auth hook, same as every other admin route --
   * in practice only ever called by chameleon-console at provisioning time.
   */
  fastify.post<{ Body: { analystEmails: string[] } }>(
    '/admin/analyst-claims',
    async (request, reply) => {
      const context = getRequestContext(request);
      context.operation = 'CREATE_ANALYST_CLAIMS';
      const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';

      try {
        const { analystEmails } = await validateRequest(createAnalystClaimsSchema, request.body);

        const claimTokens = await Promise.all(
          analystEmails.map(async (analystEmail: string) => ({
            email: analystEmail,
            claimToken: await analystAccessService.createClaim(tenantId, analystEmail),
          }))
        );

        logger.info({ correlationId: context.correlationId, tenantId, count: claimTokens.length }, 'Created analyst claim tokens');
        return reply.status(201).send({ claimTokens });
      } catch (error: unknown) {
        const err = error as { statusCode?: number; message?: string; errors?: unknown };
        if (err.statusCode === 400) {
          return reply.status(400).send({ error: err.message || 'Validation Error', errors: err.errors, statusCode: 400 });
        }
        logger.error({ correlationId: context.correlationId, error }, 'Failed to create analyst claim tokens');
        return reply.status(500).send({
          error: 'Failed to create analyst claim tokens',
          message: error instanceof Error ? error.message : String(error),
          statusCode: 500,
        });
      }
    }
  );

  /**
   * POST /admin/auditor-claims
   * Same one-time claim-link flow as POST /admin/analyst-claims above, but
   * mints credentials scoped to the auditor role (see
   * AUDITOR_CREDENTIAL_ROUTE_PATTERN in middleware/auth.ts) rather than the
   * analyst role. The claim-consumption route below is shared by both --
   * it's generic over whatever role the claim was created with.
   */
  fastify.post<{ Body: { auditorEmails: string[] } }>(
    '/admin/auditor-claims',
    async (request, reply) => {
      const context = getRequestContext(request);
      context.operation = 'CREATE_AUDITOR_CLAIMS';
      const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';

      try {
        const { auditorEmails } = await validateRequest(createAuditorClaimsSchema, request.body);

        const claimTokens = await Promise.all(
          auditorEmails.map(async (auditorEmail: string) => ({
            email: auditorEmail,
            claimToken: await analystAccessService.createClaim(tenantId, auditorEmail, 'auditor'),
          }))
        );

        logger.info({ correlationId: context.correlationId, tenantId, count: claimTokens.length }, 'Created auditor claim tokens');
        return reply.status(201).send({ claimTokens });
      } catch (error: unknown) {
        const err = error as { statusCode?: number; message?: string; errors?: unknown };
        if (err.statusCode === 400) {
          return reply.status(400).send({ error: err.message || 'Validation Error', errors: err.errors, statusCode: 400 });
        }
        logger.error({ correlationId: context.correlationId, error }, 'Failed to create auditor claim tokens');
        return reply.status(500).send({
          error: 'Failed to create auditor claim tokens',
          message: error instanceof Error ? error.message : String(error),
          statusCode: 500,
        });
      }
    }
  );

  /**
   * POST /admin/analyst-claims/:token/claim
   * Consumes a one-time claim token and issues a real API key. Deliberately
   * NOT gated by the shared-secret auth hook (see main.ts's early-return) --
   * the analyst clicking this link has neither the shared key nor a
   * credential yet. The token itself, plus the rate limit below, is the
   * entire defense here.
   */
  fastify.post<{ Params: { token: string } }>(
    '/admin/analyst-claims/:token/claim',
    { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const context = getRequestContext(request);
      context.operation = 'CLAIM_ANALYST_CREDENTIAL';

      try {
        const { token } = await validateRequest(claimAnalystTokenSchema, request.params);
        const result = await analystAccessService.claim(token);

        if (!result) {
          return reply.status(410).send({ error: 'This claim link is invalid, expired, or already used', statusCode: 410 });
        }

        logger.info(
          { correlationId: context.correlationId, analystEmail: result.analystEmail, role: result.role },
          'Scoped credential claimed'
        );
        return reply.status(200).send({ apiKey: result.apiKey, analystEmail: result.analystEmail, role: result.role });
      } catch (error: unknown) {
        const err = error as { statusCode?: number; message?: string; errors?: unknown };
        if (err.statusCode === 400) {
          return reply.status(400).send({ error: err.message || 'Validation Error', errors: err.errors, statusCode: 400 });
        }
        logger.error({ correlationId: context.correlationId, error }, 'Failed to claim analyst credential');
        return reply.status(500).send({
          error: 'Failed to claim analyst credential',
          message: error instanceof Error ? error.message : String(error),
          statusCode: 500,
        });
      }
    }
  );
}
