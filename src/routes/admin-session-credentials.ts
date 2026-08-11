import { FastifyInstance } from 'fastify';
import { AnalystAccessService } from '../services/analyst-access-service.js';
import { createLogger } from '../logging/index.js';
import { getRequestContext } from '../middleware/request-logging.js';
import { validateRequest, mintSessionCredentialSchema } from '../middleware/validation.js';

const logger = createLogger('admin-session-credentials-routes');

export interface AdminSessionCredentialsRoutesOptions {
  analystAccessService: AnalystAccessService;
}

export async function adminSessionCredentialsRoutes(
  fastify: FastifyInstance,
  options: AdminSessionCredentialsRoutesOptions
): Promise<void> {
  const { analystAccessService } = options;

  /**
   * POST /admin/session-credentials
   * Mints a short-lived, narrowly-scoped analyst credential on behalf of a
   * person the console has already authenticated in a real per-person
   * session (not the static shared-password fallback -- see
   * chameleon-console's project-context.ts, which only mints this when a
   * real session email is available). Gated by the standard shared-secret
   * auth hook, same trust class as every other admin route: only the
   * console itself calls this, never an end user directly, and never with
   * an analyst credential (this path is not in
   * ANALYST_CREDENTIAL_*_PATHS/PATTERN in middleware/auth.ts).
   */
  fastify.post<{ Body: { email: string } }>('/admin/session-credentials', async (request, reply) => {
    const context = getRequestContext(request);
    context.operation = 'MINT_SESSION_CREDENTIAL';
    const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';

    try {
      const { email } = await validateRequest(mintSessionCredentialSchema, request.body);
      const { credential, expiresAt } = await analystAccessService.mintSessionCredential(tenantId, email);

      logger.info({ correlationId: context.correlationId, tenantId, email }, 'Minted console-session credential');
      return reply.status(201).send({ credential, expiresAt: expiresAt.toISOString() });
    } catch (error: unknown) {
      const err = error as { statusCode?: number; message?: string; errors?: unknown };
      if (err.statusCode === 400) {
        return reply.status(400).send({ error: err.message || 'Validation Error', errors: err.errors, statusCode: 400 });
      }
      logger.error({ correlationId: context.correlationId, error }, 'Failed to mint console-session credential');
      return reply.status(500).send({
        error: 'Failed to mint session credential',
        message: error instanceof Error ? error.message : String(error),
        statusCode: 500,
      });
    }
  });
}
