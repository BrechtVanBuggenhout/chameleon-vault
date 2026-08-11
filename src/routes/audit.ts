import { FastifyInstance } from 'fastify';
import { PiiRegistryService } from '../services/pii-registry-service.js';
import { DeletionRequestRepository } from '../gcp/deletion-request-repository.js';
import { createLogger } from '../logging/index.js';
import { getRequestContext } from '../middleware/request-logging.js';
import type { PiiRegistryEntry } from '../types/pii-registry.js';
import type { DeletionRequest } from '../types/deletion-request.js';

const logger = createLogger('audit-routes');

export interface AuditRoutesOptions {
  piiRegistryService: PiiRegistryService;
  deletionRequestRepo: DeletionRequestRepository;
}

interface AuditEvent {
  type: 'PII_REGISTRY_DECLARED' | 'PII_REGISTRY_MODIFIED' | 'DELETION_REQUESTED';
  resourceId: string;
  actorEmail: string;
  tenantId?: string;
  timestamp: string;
}

const MAX_PAGE_SIZE = 200;
const DEFAULT_PAGE_SIZE = 50;

// Firestore's Node client returns a Timestamp (toDate()/toMillis()), not a
// native Date, for a doc's timestamp fields -- same defensive handling as
// formatTimestamp() in routes/crypto.ts and firestore-registry.ts.
function toIso(value: unknown): string | undefined {
  if (!value) return undefined;
  if (typeof (value as { toISOString?: () => string }).toISOString === 'function') {
    return (value as { toISOString: () => string }).toISOString();
  }
  if (typeof (value as { toDate?: () => Date }).toDate === 'function') {
    return (value as { toDate: () => Date }).toDate().toISOString();
  }
  return String(value);
}

/**
 * A registry entry carries at most two attributable moments: when it was
 * first declared, and (if different) when it was last modified. Both are
 * surfaced as separate events rather than collapsed into one, so an actor
 * who only ever edited a resource someone else declared still shows up.
 */
function eventsForRegistryEntry(entry: PiiRegistryEntry, actorFilter?: string): AuditEvent[] {
  const events: AuditEvent[] = [];
  if (entry.declaredBy && (!actorFilter || entry.declaredBy === actorFilter) && entry.createdAt) {
    events.push({
      type: 'PII_REGISTRY_DECLARED',
      resourceId: entry.resourceId,
      actorEmail: entry.declaredBy,
      tenantId: entry.tenantId,
      timestamp: entry.createdAt,
    });
  }
  if (
    entry.lastModifiedBy &&
    (!actorFilter || entry.lastModifiedBy === actorFilter) &&
    entry.updatedAt &&
    entry.updatedAt !== entry.createdAt
  ) {
    events.push({
      type: 'PII_REGISTRY_MODIFIED',
      resourceId: entry.resourceId,
      actorEmail: entry.lastModifiedBy,
      tenantId: entry.tenantId,
      timestamp: entry.updatedAt,
    });
  }
  return events;
}

function eventForDeletionRequest(request: DeletionRequest): AuditEvent | null {
  if (!request.requested_by) return null;
  const timestamp = toIso(request.created_at);
  if (!timestamp) return null;
  return {
    type: 'DELETION_REQUESTED',
    resourceId: request.user_id,
    actorEmail: request.requested_by,
    tenantId: request.tenant_id,
    timestamp,
  };
}

function parsePageSize(raw: unknown): number {
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_PAGE_SIZE;
  return Math.min(parsed, MAX_PAGE_SIZE);
}

export async function auditRoutes(fastify: FastifyInstance, options: AuditRoutesOptions): Promise<void> {
  const { piiRegistryService, deletionRequestRepo } = options;

  /**
   * GET /audit/actor/:email
   * Every registry declaration/modification and deletion request a given
   * person's credential (analyst or console-session) made, newest first.
   * Combines an in-memory scan of the registry (already fully loaded --
   * see PiiRegistryService) with a real Firestore query for deletion
   * requests, since those aren't cached in memory.
   */
  fastify.get<{ Params: { email: string }; Querystring: { limit?: string } }>(
    '/audit/actor/:email',
    async (request, reply) => {
      const context = getRequestContext(request);
      context.operation = 'AUDIT_BY_ACTOR';
      const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';
      const { email } = request.params;
      const limit = parsePageSize(request.query.limit);

      try {
        const registryEvents = piiRegistryService
          .listEntries({ tenantId, actorEmail: email })
          .flatMap((entry) => eventsForRegistryEntry(entry, email));

        const deletionRequests = await deletionRequestRepo.listByRequestedBy(email, tenantId, MAX_PAGE_SIZE);
        const deletionEvents = deletionRequests
          .map(eventForDeletionRequest)
          .filter((event): event is AuditEvent => event !== null);

        const events = [...registryEvents, ...deletionEvents]
          .sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1))
          .slice(0, limit);

        return reply.send({ actorEmail: email, events, count: events.length, timestamp: new Date().toISOString() });
      } catch (error) {
        logger.error({ correlationId: context.correlationId, error, email }, 'Failed to load audit trail for actor');
        return reply.status(500).send({ error: 'Failed to load audit trail', statusCode: 500 });
      }
    }
  );

  /**
   * GET /audit/resource/:resourceId
   * Who declared and last modified a specific PII registry resource.
   * Scoped to registry resources -- a deletion request's natural "resource"
   * (a user id) is already directly queryable via
   * GET /deletion-requests/:deletionRequestId, so this endpoint doesn't
   * duplicate that.
   */
  fastify.get<{ Params: { resourceId: string } }>('/audit/resource/:resourceId', async (request, reply) => {
    const context = getRequestContext(request);
    context.operation = 'AUDIT_BY_RESOURCE';
    const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';
    const { resourceId } = request.params;

    try {
      const entry = piiRegistryService.getEntry(decodeURIComponent(resourceId), tenantId);
      if (!entry) {
        return reply.status(404).send({ error: 'No registry entry found for this resource', statusCode: 404 });
      }

      const events = eventsForRegistryEntry(entry).sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));
      return reply.send({ resourceId: entry.resourceId, events, count: events.length, timestamp: new Date().toISOString() });
    } catch (error) {
      logger.error({ correlationId: context.correlationId, error, resourceId }, 'Failed to load audit trail for resource');
      return reply.status(500).send({ error: 'Failed to load audit trail', statusCode: 500 });
    }
  });
}
