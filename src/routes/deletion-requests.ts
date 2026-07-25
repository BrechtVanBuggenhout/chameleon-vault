import { FastifyInstance } from 'fastify';
import { DeletionRequestService } from '../services/deletion-request-service.js';
import { createLogger } from '../logging/index.js';
import { getRequestContext } from '../middleware/request-logging.js';
import { validateRequest } from '../middleware/validation.js';
import {
  createDeletionRequestSchema,
  getDeletionRequestSchema,
  advanceDeletionRequestSchema,
} from '../middleware/validation.js'; // New validation schemas needed
import { DeletionRequestStatus } from '../types/deletion-request.js';

const logger = createLogger('deletion-request-routes');

export interface DeletionRequestRoutesOptions {
  deletionRequestService: DeletionRequestService;
}

export async function deletionRequestRoutes(fastify: FastifyInstance, options: DeletionRequestRoutesOptions): Promise<void> {
  const { deletionRequestService } = options;

  /**
   * POST /deletion-requests
   * Initiates a new deletion request for a user.
   */
  fastify.post<{ Body: { userId?: string; user_id?: string; operationId?: string; operation_id?: string } }>(
    '/deletion-requests',
    async (request, reply) => {
      const context = getRequestContext(request);
      context.operation = 'CREATE_DELETION_REQUEST';
      const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';

      try {
        const body = await validateRequest(createDeletionRequestSchema, request.body) as any;
        const userId = body.userId || body.user_id;
        const operationId = body.operationId || body.operation_id;
        context.userId = userId;
        context.operationId = operationId;

        const deletionRequest = await deletionRequestService.createRequest(userId, operationId, tenantId);

        logger.info({ correlationId: context.correlationId, userId, deletionRequestId: deletionRequest.deletion_request_id, status: deletionRequest.status }, 'Deletion request created/retrieved');
        
        return reply.status(201).send({
          ...deletionRequest,
          // Explicitly add camelCase aliases for consistency in API responses
          // The underlying DeletionRequest object uses snake_case
          userId: deletionRequest.user_id,
          deletionRequestId: deletionRequest.deletion_request_id,
        });
      } catch (error: unknown) {
        logger.error({ correlationId: context.correlationId, error, userId: (request.body as any)?.userId || (request.body as any)?.user_id }, 'Failed to create deletion request');
        return reply.status(500).send({
          error: 'Failed to create deletion request',
          message: error instanceof Error ? error.message : String(error),
          statusCode: 500,
        });
      }
    }
  );

  /**
   * GET /deletion-requests/:deletionRequestId
   * Retrieves the status and details of a specific deletion request.
   */
  fastify.get<{ Params: { deletionRequestId: string } }>(
    '/deletion-requests/:deletionRequestId',
    async (request, reply) => {
      const context = getRequestContext(request);
      context.operation = 'GET_DELETION_REQUEST';
      const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';

      try {
        const { deletionRequestId } = await validateRequest(getDeletionRequestSchema, request.params);
        context.deletionRequestId = deletionRequestId;

        const deletionRequest = await deletionRequestService.getRequest(deletionRequestId);

        // 404 (not 403) on a tenant mismatch: don't reveal that a record
        // exists under a different tenant to a caller that can't see it.
        if (!deletionRequest || (deletionRequest.tenant_id ?? 'default-tenant') !== tenantId) {
          logger.warn({ correlationId: context.correlationId, deletionRequestId }, 'Deletion request not found');
          return reply.status(404).send({ error: 'Deletion request not found', statusCode: 404 });
        }

        logger.info({ correlationId: context.correlationId, deletionRequestId, status: deletionRequest.status }, 'Retrieved deletion request');
        return reply.status(200).send({
          ...deletionRequest,
          // Explicitly add camelCase aliases for consistency in API responses
          userId: deletionRequest.user_id,
          deletionRequestId: deletionRequest.deletion_request_id,
        });
      } catch (error: unknown) {
        logger.error({ correlationId: context.correlationId, error, deletionRequestId: request.params.deletionRequestId }, 'Failed to get deletion request');
        return reply.status(500).send({
          error: 'Failed to get deletion request',
          message: error instanceof Error ? error.message : String(error),
          statusCode: 500,
        });
      }
    }
  );

  /**
   * POST /deletion-requests/:deletionRequestId/advance
   * Advances the state of a deletion request.
   */
  fastify.post<{ Params: { deletionRequestId: string }; Body: { newStatus: DeletionRequestStatus; operationId: string } }>(
    '/deletion-requests/:deletionRequestId/advance',
    async (request, reply) => {
      const context = getRequestContext(request);
      context.operation = 'ADVANCE_DELETION_REQUEST';

      try {
        const { deletionRequestId } = await validateRequest(getDeletionRequestSchema, request.params);
        const body = await validateRequest(advanceDeletionRequestSchema, request.body);
        
        const newStatus = body.newStatus || body.new_status;
        const opId = body.operationId || body.operation_id;

        const updatedRequest = await deletionRequestService.advanceRequest(deletionRequestId, newStatus, opId);
        logger.info({ correlationId: context.correlationId, deletionRequestId, newStatus: updatedRequest.status }, 'Advanced deletion request status');
        return reply.status(200).send({
          ...updatedRequest,
          // Explicitly add camelCase aliases for consistency in API responses
          userId: updatedRequest.user_id,
          deletionRequestId: updatedRequest.deletion_request_id,
        });
      } catch (error: unknown) {
        logger.error({ correlationId: context.correlationId, error, deletionRequestId: request.params.deletionRequestId }, 'Failed to advance deletion request');
        return reply.status(500).send({ error: 'Failed to advance deletion request', message: error instanceof Error ? error.message : String(error), statusCode: 500 });
      }
    }
  );
}
