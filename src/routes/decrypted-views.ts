import { FastifyInstance } from 'fastify';
import { DecryptedViewService } from '../services/decrypted-view-service.js';
import { DecryptedViewsRepository } from '../gcp/decrypted-views-repository.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('decrypted-views-routes');

export interface DecryptedViewsRoutesOptions {
  decryptedViewService: DecryptedViewService;
  decryptedViewsRepository: DecryptedViewsRepository;
}

interface DeclareViewBody {
  viewName?: string;
  declaredFields?: string[];
  businessJustification?: string;
  createdBy?: string;
  consumerServiceAccount?: string;
}

/**
 * Console-facing management routes -- create/list/revoke a decrypted view
 * declaration. Gated by the same shared VAULT_API_KEY hook as every other
 * non-exempt route (see middleware/auth.ts); this is a normal declare-style
 * operation, not one that needs a different auth tier. The actual decrypt
 * capability lives entirely in decrypted-views-decrypt.ts, a structurally
 * separate route with its own auth.
 */
export async function decryptedViewsRoutes(
  fastify: FastifyInstance,
  options: DecryptedViewsRoutesOptions
): Promise<void> {
  const { decryptedViewService, decryptedViewsRepository } = options;

  fastify.post('/decrypted-views', async (request, reply) => {
    const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';
    const body = (request.body as DeclareViewBody) || {};

    try {
      const declaration = await decryptedViewService.declareView({
        tenantId,
        viewName: body.viewName ?? '',
        declaredFields: body.declaredFields ?? [],
        businessJustification: body.businessJustification ?? '',
        createdBy: body.createdBy ?? 'unknown',
        consumerServiceAccount: body.consumerServiceAccount ?? '',
      });
      return reply.status(201).send(declaration);
    } catch (error) {
      logger.error({ error, tenantId, viewName: body.viewName }, 'Failed to declare decrypted view');
      return reply.status(400).send({
        statusCode: 400,
        error: 'Failed to declare decrypted view',
        message: error instanceof Error ? error.message : String(error),
      });
    }
  });

  fastify.get('/decrypted-views', async (request) => {
    const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';
    const views = await decryptedViewsRepository.listByTenant(tenantId);
    return { views };
  });

  /**
   * Field names actually synced into pii_vault for this tenant -- lets the
   * console offer a real picker instead of requiring the customer to know
   * exact field_name strings by heart. Same query declareView() itself
   * uses to validate a declaration, exposed read-only here.
   */
  fastify.get('/decrypted-views/available-fields', async (request, reply) => {
    const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';
    try {
      const fields = await decryptedViewService.getAvailableFields(tenantId);
      if (fields.length > 0) {
        return { fields };
      }
      // Nothing found for this tenant -- before implying "never synced,"
      // check whether data actually landed under a different tenant_id
      // (a real, confirmed failure mode -- see getDistinctSyncedTenantIds'
      // own docstring). Best-effort: a failure here shouldn't turn an
      // already-legitimate empty result into a 500.
      let otherTenantIdsWithData: string[] | undefined;
      try {
        const others = (await decryptedViewService.getDistinctSyncedTenantIds()).filter((t) => t !== tenantId);
        if (others.length > 0) otherTenantIdsWithData = others;
      } catch (diagnosticError) {
        logger.warn({ diagnosticError, tenantId }, 'Failed to check for a tenant_id mismatch (non-fatal)');
      }
      return { fields, ...(otherTenantIdsWithData ? { otherTenantIdsWithData } : {}) };
    } catch (error) {
      logger.error({ error, tenantId }, 'Failed to list available pii_vault fields');
      return reply.status(500).send({
        statusCode: 500,
        error: 'Failed to list available fields',
        message: error instanceof Error ? error.message : String(error),
      });
    }
  });

  fastify.delete('/decrypted-views/:viewName', async (request, reply) => {
    const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';
    const { viewName } = request.params as { viewName: string };
    const body = (request.body as { revokedBy?: string }) || {};

    try {
      const revoked = await decryptedViewService.revokeView(tenantId, viewName, body.revokedBy ?? 'unknown');
      if (!revoked) {
        return reply.status(404).send({ statusCode: 404, error: 'Decrypted view not found or already revoked' });
      }
      return revoked;
    } catch (error) {
      logger.error({ error, tenantId, viewName }, 'Failed to revoke decrypted view');
      return reply.status(500).send({
        statusCode: 500,
        error: 'Failed to revoke decrypted view',
        message: error instanceof Error ? error.message : String(error),
      });
    }
  });
}
