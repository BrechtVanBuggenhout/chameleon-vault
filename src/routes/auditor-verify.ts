import { FastifyInstance } from 'fastify';
import { FirestoreRegistry } from '../gcp/firestore-registry.js';
import { createLogger } from '../logging/index.js';
import { getRequestContext } from '../middleware/request-logging.js';

const logger = createLogger('auditor-verify-routes');

export interface AuditorVerifyRoutesOptions {
  firestoreRegistry: FirestoreRegistry;
}

/**
 * GET /audit/key-status/:userId
 *
 * The one route an auditor credential can reach (see
 * middleware/auth.ts's AUDITOR_CREDENTIAL_ROUTE_PATTERN). Deliberately
 * answers exactly one question -- "is there currently recoverable key
 * material for this user" -- via FirestoreRegistry.hasActiveKeyMaterial, a
 * small, separately-reviewable function that isn't shared with any other
 * code path. The point of this route existing at all is that an auditor
 * doesn't have to trust the same application logic that issues the
 * certificate; this is a second, narrower, independently-checkable path to
 * the same underlying fact.
 *
 * Every call is logged with the credential's attributed email (see
 * requestContext.analystEmail, populated by the auth hook for any scoped
 * credential regardless of role) -- an auditor's queries about a specific
 * user are themselves audit-relevant.
 */
export async function auditorVerifyRoutes(fastify: FastifyInstance, options: AuditorVerifyRoutesOptions): Promise<void> {
  const { firestoreRegistry } = options;

  fastify.get<{ Params: { userId: string } }>(
    '/audit/key-status/:userId',
    { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const context = getRequestContext(request);
      context.operation = 'AUDITOR_VERIFY_KEY_STATUS';
      const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';
      const { userId } = request.params;

      try {
        const hasActiveKeyMaterial = await firestoreRegistry.hasActiveKeyMaterial(userId, tenantId);

        logger.info(
          {
            correlationId: context.correlationId,
            tenantId,
            userId,
            auditorEmail: context.analystEmail,
            hasActiveKeyMaterial,
          },
          'Auditor checked key erasure status'
        );

        return reply.status(200).send({ userId, hasActiveKeyMaterial });
      } catch (error: unknown) {
        logger.error({ correlationId: context.correlationId, error, userId }, 'Failed to check key status for auditor');
        return reply.status(500).send({
          error: 'Failed to check key status',
          message: error instanceof Error ? error.message : String(error),
          statusCode: 500,
        });
      }
    }
  );
}
