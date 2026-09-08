import { FastifyInstance } from 'fastify';
import { AnalystAccessService } from '../services/analyst-access-service.js';
import { createLogger } from '../logging/index.js';
import { getRequestContext } from '../middleware/request-logging.js';
import { validateRequest, mintServiceCredentialSchema, revokeServiceCredentialSchema } from '../middleware/validation.js';

const logger = createLogger('admin-service-credentials-routes');

export interface AdminServiceCredentialsRoutesOptions {
  analystAccessService: AnalystAccessService;
}

export async function adminServiceCredentialsRoutes(
  fastify: FastifyInstance,
  options: AdminServiceCredentialsRoutesOptions
): Promise<void> {
  const { analystAccessService } = options;

  /**
   * POST /admin/service-credentials
   * Mints a durable credential for an external system to trigger deletions
   * on its own behalf -- e.g. another platform that wants to call Chameleon
   * directly when one of its own users asks to be forgotten. Gated by the
   * standard shared-secret auth hook, same as every other admin route: only
   * an operator with the shared VAULT_API_KEY can provision one, no
   * self-serve minting. See middleware/auth.ts's
   * isServiceCredentialAllowedPath for exactly what the minted credential
   * can do (create/check/advance a deletion request, read the resulting
   * certificate -- nothing else).
   */
  fastify.post<{ Body: { callerName: string } }>('/admin/service-credentials', async (request, reply) => {
    const context = getRequestContext(request);
    context.operation = 'MINT_SERVICE_CREDENTIAL';
    const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';

    try {
      const { callerName } = await validateRequest(mintServiceCredentialSchema, request.body);
      const { credential } = await analystAccessService.mintServiceCredential(tenantId, callerName);

      logger.info({ correlationId: context.correlationId, tenantId, callerName }, 'Minted service credential');
      return reply.status(201).send({ credential, tenantId, callerName });
    } catch (error: unknown) {
      const err = error as { statusCode?: number; message?: string; errors?: unknown };
      if (err.statusCode === 400) {
        return reply.status(400).send({ error: err.message || 'Validation Error', errors: err.errors, statusCode: 400 });
      }
      logger.error({ correlationId: context.correlationId, error }, 'Failed to mint service credential');
      return reply.status(500).send({
        error: 'Failed to mint service credential',
        message: error instanceof Error ? error.message : String(error),
        statusCode: 500,
      });
    }
  });

  /**
   * POST /admin/service-credentials/revoke
   * Revokes every standing credential issued for (tenantId, callerName) --
   * "cut off this integration," not "revoke one specific secret." Returns
   * revokedCount so a caller can tell a real revoke from "nothing matched
   * that name" without treating either as an error.
   */
  fastify.post<{ Body: { callerName: string } }>('/admin/service-credentials/revoke', async (request, reply) => {
    const context = getRequestContext(request);
    context.operation = 'REVOKE_SERVICE_CREDENTIAL';
    const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';

    try {
      const { callerName } = await validateRequest(revokeServiceCredentialSchema, request.body);
      const revokedCount = await analystAccessService.revokeServiceCredentials(tenantId, callerName);

      logger.info({ correlationId: context.correlationId, tenantId, callerName, revokedCount }, 'Revoked service credentials');
      return reply.status(200).send({ tenantId, callerName, revokedCount });
    } catch (error: unknown) {
      const err = error as { statusCode?: number; message?: string; errors?: unknown };
      if (err.statusCode === 400) {
        return reply.status(400).send({ error: err.message || 'Validation Error', errors: err.errors, statusCode: 400 });
      }
      logger.error({ correlationId: context.correlationId, error }, 'Failed to revoke service credentials');
      return reply.status(500).send({
        error: 'Failed to revoke service credentials',
        message: error instanceof Error ? error.message : String(error),
        statusCode: 500,
      });
    }
  });
}
