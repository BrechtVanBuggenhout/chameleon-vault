import { FastifyInstance } from 'fastify';
import { BigQueryLineageRepository } from '../gcp/bigquery-lineage.js';
import { FirestoreRegistry } from '../gcp/firestore-registry.js';
import { validateRequest, lineageEventSchema, keyStatusSchema } from '../middleware/validation.js';
import { createLogger } from '../logging/index.js';
import type { LineageDestination, UserLineage } from '../types/lineage.js';
import { JanitorService } from '../services/janitor.js';

const logger = createLogger('lineage-routes');

function hotPathDestinationsToLineage(destinations: string[] = [], lastSeen?: string): LineageDestination[] {
  const timestamp = lastSeen ? new Date(lastSeen) : new Date();
  return [...new Set(destinations)].map((name) => ({ name, lastSeen: timestamp }));
}

export interface LineageRoutesOptions {
  lineageRepository: BigQueryLineageRepository;
  firestoreRegistry: FirestoreRegistry;
  janitorService: JanitorService;
}

export async function lineageRoutes(
  fastify: FastifyInstance,
  options: LineageRoutesOptions
): Promise<void> {
  const { lineageRepository: repository, firestoreRegistry, janitorService: janitor } = options;

  /**
   * POST /lineage/events
   * Record data movement
   */
  fastify.post('/lineage/events', async (request, reply) => {
    try {
      const payload = await validateRequest(lineageEventSchema, request.body);
      const tenantId = (request.headers['x-tenant-id'] as string) || payload.tenantId || payload.tenant_id || 'default-tenant';
      const userId = payload.userId || payload.user_id;
      const dataClassification = payload.dataClassification || payload.data_classification;
      const context = payload.context || payload.metadata;
      const isResourceLevelGhostFinding = dataClassification === 'GHOST_DATA' && userId === 'UNKNOWN';
      
      // Update the user-level "Hot Path" in Firestore for the Janitor.
      // Resource-level scanner findings are audit lineage, not a real user deletion target.
      if (!isResourceLevelGhostFinding) {
        await firestoreRegistry.addDestinationToUser(userId, payload.destination, tenantId);
      }

      const eventId = await repository.recordEvent({ ...payload, userId, tenantId, context });
      
      return reply.status(201).send({
        status: 'RECORDED',
        eventId,
        timestamp: new Date().toISOString(),
      });
    } catch (error: unknown) {
      logger.error({ error, body: request.body }, 'Failed to record lineage event');
      const err = error as { statusCode?: number; message?: string };
      return reply.status(err.statusCode || 500).send({
        error: err.message || 'Internal server error',
        statusCode: err.statusCode || 500
      });
    }
  });

  /**
   * GET /lineage/user/:userId
   * List destinations for a user
   */
  fastify.get('/lineage/user/:userId', async (request, reply) => {
    try {
      const { userId } = await validateRequest(keyStatusSchema, request.params);
      const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';
      const lineage: UserLineage = await repository.getUserLineage(userId, tenantId);
      let destinations = lineage.destinations;
      let readModel = 'bigquery';

      if (destinations.length === 0) {
        const keyStatus = await firestoreRegistry.getKeyStatus(userId, tenantId);
        destinations = hotPathDestinationsToLineage(
          keyStatus?.destinations,
          keyStatus?.shred_at || keyStatus?.shredAt || keyStatus?.rotated_at || keyStatus?.rotatedAt || keyStatus?.created_at || keyStatus?.createdAt
        );
        readModel = destinations.length > 0 ? 'firestore-hot-path' : 'bigquery';
      }
      
      return reply.send({
        userId: lineage.userId,
        tenantId,
        destinations,
        readModel,
        timestamp: new Date().toISOString(),
      });
    } catch (error: unknown) {
      const err = error as { statusCode?: number; message?: string };
      return reply.status(err.statusCode || 500).send({
        error: err.message || 'Internal server error',
        statusCode: err.statusCode || 500
      });
    }
  });

  /**
   * GET /lineage/deletion-plan/:userId
   * Preview impact of shredding
   */
  fastify.get('/lineage/deletion-plan/:userId', async (request, reply) => {
    try {
      const { userId } = await validateRequest(keyStatusSchema, request.params);
      const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';
      
      const cleanupTasks = await janitor.createCleanupPlan(userId, tenantId);
      const lineage = await repository.getUserLineage(userId, tenantId);
      const ghostDataSummary = await repository.getGhostDataFindings(userId, tenantId);
      const keyStatus = lineage.destinations.length === 0
        ? await firestoreRegistry.getKeyStatus(userId, tenantId)
        : null;
      const lineageDestinations = lineage.destinations.length > 0
        ? lineage.destinations.map((destination) => destination.name)
        : keyStatus?.destinations || [];
      const impactedDestinations = [...new Set([
        ...lineageDestinations,
        ...cleanupTasks.map((task) => task.destination),
      ])];

      if (impactedDestinations.length === 0 && ghostDataSummary.length === 0) {
        return reply.status(404).send({
          error: 'User not found in lineage graph',
          statusCode: 404,
        });
      }

      return reply.send({
        userId,
        tenantId,
        impactedDestinations,
        mathematicalErasure: {
          status: 'PENDING',
          // These are the static stores where encryption makes data unrecoverable
          stores: ['bigquery', 'gcs-landing-zone', 'firestore-logs'],
        },
        ghostDataSummary,
        timestamp: new Date().toISOString(),
      });
    } catch (error: unknown) {
      const err = error as { statusCode?: number; message?: string };
      return reply.status(err.statusCode || 500).send({
        error: err.message || 'Internal server error',
        statusCode: err.statusCode || 500
      });
    }
  });
};
